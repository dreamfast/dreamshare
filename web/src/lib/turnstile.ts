// Minimal loader for the Cloudflare Turnstile widget. The script is only
// fetched when the server says the challenge is enforced, so recipient
// pages never load a third-party script at all.
//
// Tokens are single use and expire after a few minutes, the caller owns
// resetting the widget after a failed submit.

export interface TurnstileHandle {
  reset: () => void
  remove: () => void
}

export interface WidgetCallbacks {
  onToken: (token: string) => void
  onExpire: () => void
}

interface TurnstileGlobal {
  render: (
    el: HTMLElement | string,
    opts: {
      sitekey: string
      callback: (token: string) => void
      'expired-callback': () => void
      'error-callback': () => void
      theme: 'light' | 'dark' | 'auto'
      appearance: 'always' | 'interaction-only'
    },
  ) => string
  reset: (id?: string) => void
  remove: (id: string) => void
}

declare global {
  interface Window {
    turnstile?: TurnstileGlobal
  }
}

const SRC = 'https://challenges.cloudflare.com/turnstile/v0/api.js'

let loading: Promise<TurnstileGlobal> | null = null

export function loadTurnstile(): Promise<TurnstileGlobal> {
  if (typeof window === 'undefined') return Promise.reject(new Error('no window'))
  if (window.turnstile) return Promise.resolve(window.turnstile)
  if (loading) return loading
  loading = new Promise((resolve, reject) => {
    const script = document.createElement('script')
    script.src = SRC
    script.async = true
    script.defer = true
    script.onload = () => {
      if (window.turnstile) resolve(window.turnstile)
      else reject(new Error('turnstile script loaded without the api'))
    }
    script.onerror = () => {
      loading = null
      reject(new Error('turnstile script failed to load'))
    }
    document.head.appendChild(script)
  })
  return loading
}

export function renderWidget(el: HTMLElement, siteKey: string, cb: WidgetCallbacks): TurnstileHandle {
  const api = window.turnstile
  if (!api) throw new Error('turnstile not loaded')
  // interaction-only keeps the form clean, the box appears by itself when
  // the challenge needs a human
  const id = api.render(el, {
    sitekey: siteKey,
    callback: cb.onToken,
    'expired-callback': cb.onExpire,
    'error-callback': cb.onExpire,
    theme: 'light',
    appearance: 'interaction-only',
  })
  return {
    reset: () => api.reset(id),
    remove: () => api.remove(id),
  }
}
