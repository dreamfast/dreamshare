<script setup lang="ts">
// The staff room. The server gates every /admin/api route behind the
// ip allowlist and the session cookie, this view only renders what those
// endpoints already answer.
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { bootstrap, csrfCookie, type BootstrapInfo } from '../lib/api'
import { buildThemedQr } from '../lib/qr'
import { loadTurnstile, renderWidget, type TurnstileHandle } from '../lib/turnstile'

type Overview = {
  active_shares: number
  in_flight_shares: number
  terminal_shares: number
  bytes_stored: number
  bytes_today: number
  events_24h: number
  check_fails_24h: number
  db_bytes: number
}

const router = useRouter()
const httpStatusNotFound = 404

const email = ref('')
const password = ref('')
const totp = ref('')
const loginError = ref('')
const busy = ref(false)
const authed = ref(false)
const overview = ref<Overview | null>(null)

const info = ref<BootstrapInfo | null>(null)
const turnstileBox = ref<HTMLElement | null>(null)
const turnstileToken = ref('')
let widget: TurnstileHandle | null = null
const enforced = computed(() => info.value?.turnstile.enforced ?? false)

// the enrolment flow
const enrolling = ref(false)
const candidate = ref<{ secret: string; otpauth: string } | null>(null)
const candidateQr = ref('')
const enrolCode = ref('')
const enrolPassword = ref('')
const enrolError = ref('')
const enrolDone = ref(false)

async function post(url: string, body: unknown, method = 'POST'): Promise<Response> {
  const csrf = csrfCookie()
  return fetch(url, {
    method,
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrf,
      ...(turnstileToken.value ? { 'X-Turnstile-Token': turnstileToken.value } : {}),
    },
    body: JSON.stringify(body),
  })
}

async function login(): Promise<void> {
  if (busy.value) return
  busy.value = true
  loginError.value = ''
  try {
    const resp = await post('/admin/login', {
      email: email.value,
      password: password.value,
      totp: totp.value,
    })
    if (!resp.ok) {
      loginError.value = 'That did not sign in. Check the address, password and code.'
      widget?.reset()
      turnstileToken.value = ''
      return
    }
    await loadOverview()
    probe.value = 'authed'
  } catch (e) {
    loginError.value = (e as Error).message
  } finally {
    busy.value = false
  }
}

async function loadOverview(): Promise<void> {
  const resp = await fetch('/admin/api/overview')
  if (!resp.ok) {
    authed.value = false
    return
  }
  overview.value = (await resp.json()) as Overview
  authed.value = true
}

async function logout(): Promise<void> {
  await post('/admin/logout', {})
  authed.value = false
  overview.value = null
  probe.value = 'login'
}

async function beginEnrol(): Promise<void> {
  enrolError.value = ''
  enrolDone.value = false
  const resp = await post('/admin/api/totp/begin', { email: email.value })
  if (!resp.ok) {
    enrolError.value = 'Could not start enrolment.'
    return
  }
  candidate.value = (await resp.json()) as { secret: string; otpauth: string }
  candidateQr.value = buildThemedQr(candidate.value.otpauth)
  enrolling.value = true
}

async function confirmEnrol(): Promise<void> {
  if (!candidate.value) return
  enrolError.value = ''
  const resp = await post('/admin/api/totp/confirm', {
    email: email.value,
    password: enrolPassword.value,
    secret: candidate.value.secret,
    code: enrolCode.value,
  })
  if (!resp.ok) {
    enrolError.value = 'The code or password was refused. Nothing changed.'
    return
  }
  enrolling.value = false
  candidate.value = null
  enrolDone.value = true
}

async function disableEnrol(): Promise<void> {
  enrolError.value = ''
  const resp = await post('/admin/api/totp', { email: email.value, password: enrolPassword.value }, 'DELETE')
  if (!resp.ok) {
    enrolError.value = 'The password was refused. Nothing changed.'
    return
  }
  enrolDone.value = false
}

function fmtBytes(n: number): string {
  if (n >= 1 << 30) return `${(n / (1 << 30)).toFixed(1)} GB`
  if (n >= 1 << 20) return `${(n / (1 << 20)).toFixed(1)} MB`
  if (n >= 1 << 10) return `${(n / (1 << 10)).toFixed(0)} KB`
  return `${n} B`
}

// the challenge renders only when the server enforces it, exactly like
// the sending room
watch([() => info.value?.turnstile.site_key, authed] as const, ([siteKey, isIn]) => {
  if (widget) {
    widget.remove()
    widget = null
    turnstileToken.value = ''
  }
  if (!siteKey || isIn) return
  void loadTurnstile()
    .then(() => {
      if (!turnstileBox.value || authed.value) return
      widget = renderWidget(turnstileBox.value, siteKey, {
        onToken: (t) => (turnstileToken.value = t),
        onExpire: () => widget?.reset(),
      })
    })
    .catch(() => {
      loginError.value = 'cannot load the human check'
    })
})

// the probe: an unlisted address gets the same 404 as any unknown route
// and lands home, an allowlisted one sees the login, a session sees the
// room. the staff area never confirms itself to anyone else
const probe = ref<'probing' | 'denied' | 'login' | 'authed'>('probing')

onMounted(async () => {
  try {
    info.value = await bootstrap()
  } catch {
    loginError.value = 'cannot reach the server'
  }
  const resp = await fetch('/admin/api/session')
  if (resp.status === httpStatusNotFound) {
    router.replace('/')
    return
  }
  probe.value = resp.ok ? 'authed' : 'login'
  if (probe.value === 'authed') await loadOverview()
})

onUnmounted(() => {
  widget?.remove()
  widget = null
})
</script>

<template>
  <div class="stage">
    <div v-if="probe !== 'authed'" class="card login-card" v-show="probe === 'login'">
      <h1>Staff sign in</h1>
      <p class="sub">The admin area answers only to allowlisted addresses.</p>
      <form @submit.prevent="login()">
        <label class="field">
          <span>Email</span>
          <input v-model="email" type="email" autocomplete="username" />
        </label>
        <label class="field">
          <span>Password</span>
          <input v-model="password" type="password" autocomplete="current-password" />
        </label>
        <label class="field">
          <span>Authenticator code <em class="opt">if enrolled</em></span>
          <input v-model="totp" inputmode="numeric" autocomplete="one-time-code" />
        </label>
        <div v-if="enforced" ref="turnstileBox" class="ts-box"></div>
        <p v-if="loginError" class="error" role="alert">{{ loginError }}</p>
        <button type="submit" class="btn-primary" :disabled="busy">
          {{ busy ? 'Signing in…' : 'Sign in' }}
        </button>
      </form>
    </div>

    <div v-else class="card admin-card">
      <header class="head">
        <h1>Overview</h1>
        <button type="button" class="btn-ghost" @click="logout()">Sign out</button>
      </header>

      <dl v-if="overview" class="stats">
        <div>
          <dt>Active shares</dt>
          <dd>{{ overview.active_shares }}</dd>
        </div>
        <div>
          <dt>Still uploading</dt>
          <dd>{{ overview.in_flight_shares }}</dd>
        </div>
        <div>
          <dt>Terminal</dt>
          <dd>{{ overview.terminal_shares }}</dd>
        </div>
        <div>
          <dt>Stored</dt>
          <dd>{{ fmtBytes(overview.bytes_stored) }}</dd>
        </div>
        <div>
          <dt>Bytes today</dt>
          <dd>{{ fmtBytes(overview.bytes_today) }}</dd>
        </div>
        <div>
          <dt>Events 24h</dt>
          <dd>{{ overview.events_24h }}</dd>
        </div>
        <div>
          <dt>Key check fails</dt>
          <dd>{{ overview.check_fails_24h }}</dd>
        </div>
        <div>
          <dt>Database</dt>
          <dd>{{ fmtBytes(overview.db_bytes) }}</dd>
        </div>
      </dl>

      <section class="totp">
        <h2>Two factor</h2>
        <p v-if="enrolDone" class="totp-state on">An authenticator is enrolled. Sign in asks for its code.</p>
        <p v-else class="totp-state">No authenticator is enrolled.</p>

        <template v-if="!enrolling && !enrolDone">
          <button type="button" class="btn-primary" @click="beginEnrol()">Enrol an authenticator</button>
        </template>

        <template v-else-if="enrolling && candidate">
          <p class="sub">Scan with your authenticator app, or type the secret in by hand.</p>
          <div class="enrol-grid">
            <div v-if="candidateQr" class="qr" v-html="candidateQr"></div>
            <code class="secret">{{ candidate.secret }}</code>
          </div>
          <div class="enrol-form">
            <input
              v-model="enrolCode"
              inputmode="numeric"
              placeholder="6 digit code"
              aria-label="Authenticator code"
            />
            <input
              v-model="enrolPassword"
              type="password"
              placeholder="Admin password"
              aria-label="Admin password"
              autocomplete="current-password"
            />
            <button type="button" class="btn-primary" @click="confirmEnrol()">Confirm</button>
          </div>
        </template>

        <template v-else-if="enrolDone">
          <div class="enrol-form">
            <input
              v-model="enrolPassword"
              type="password"
              placeholder="Admin password"
              aria-label="Admin password"
              autocomplete="current-password"
            />
            <button type="button" class="btn-ghost" @click="disableEnrol()">Remove the factor</button>
          </div>
        </template>

        <p v-if="enrolError" class="error" role="alert">{{ enrolError }}</p>
      </section>
    </div>
  </div>
</template>

<style scoped>
.stage {
  min-height: calc(100vh - 15rem);
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
}

.card {
  background: var(--card);
  border: 1px solid var(--outline-soft);
  border-radius: 16px;
  padding: 2rem;
  box-shadow: 0 20px 48px rgba(52, 71, 97, 0.12);
}

.login-card {
  width: min(26rem, calc(100vw - 2rem));
  display: flex;
  flex-direction: column;
  gap: 0.6rem;
}

.login-card h1,
.admin-card h1 {
  font-family: var(--font-display);
  color: var(--heading);
  font-size: 1.4rem;
  margin: 0;
}

.sub {
  color: var(--body);
  font-size: 0.9rem;
  margin: 0.2rem 0 0;
}

.field {
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
  margin: 0.7rem 0;
}

.field span {
  font-size: 0.85rem;
  color: var(--heading);
  font-weight: 500;
}

.opt {
  color: var(--body);
  font-style: normal;
  font-weight: 400;
}

.ts-box {
  min-height: 65px;
  display: flex;
  justify-content: center;
  margin: 0.6rem 0;
}

.error {
  color: var(--danger, #b3261e);
  background: rgba(179, 38, 30, 0.07);
  border-radius: 8px;
  padding: 0.6rem 0.8rem;
  font-size: 0.85rem;
  margin: 0.6rem 0;
}

.admin-card {
  width: min(40rem, calc(100vw - 2rem));
  display: flex;
  flex-direction: column;
  gap: 1.6rem;
}

.head {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(9rem, 1fr));
  gap: 0.8rem;
  margin: 0;
}

.stats > div {
  background: var(--surface-low, #f1f3fa);
  border-radius: 10px;
  padding: 0.7rem 0.9rem;
}

.stats dt {
  font-size: 0.75rem;
  color: var(--body);
}

.stats dd {
  margin: 0.2rem 0 0;
  font-size: 1.15rem;
  color: var(--heading);
  font-weight: 600;
}

.totp h2 {
  font-size: 1.05rem;
  color: var(--heading);
  margin: 0 0 0.4rem;
}

.totp-state {
  color: var(--body);
  font-size: 0.9rem;
  margin: 0 0 0.8rem;
}

.totp-state.on {
  color: var(--heading);
}

.enrol-grid {
  display: flex;
  align-items: center;
  gap: 1rem;
  margin: 0.8rem 0;
  flex-wrap: wrap;
}

.enrol-grid .qr {
  width: 8.5rem;
  height: 8.5rem;
}

.enrol-grid .qr :deep(svg) {
  width: 100%;
  height: 100%;
}

.secret {
  font-size: 0.85rem;
  background: var(--surface-low, #f1f3fa);
  border-radius: 8px;
  padding: 0.5rem 0.7rem;
  overflow-wrap: anywhere;
}

.enrol-form {
  display: flex;
  gap: 0.6rem;
  flex-wrap: wrap;
  margin-top: 0.6rem;
}

.enrol-form input {
  padding: 10px 14px;
  border: 1px solid var(--outline-soft);
  border-radius: 10px;
  font-size: 0.9rem;
  font-family: inherit;
  background: var(--card);
  color: var(--heading);
}
</style>
