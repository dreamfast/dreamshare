<script setup lang="ts">
// The sending room: a small card that carries the upload from the human
// check to the finished link. the form is gone, only the recap, per file
// progress and the turnstile confirmation live here.
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { onBeforeRouteLeave, useRouter } from 'vue-router'
import { bootstrap, type BootstrapInfo } from '../lib/api'
import { cancelSend, retrySend, sendStarted, sendState, startSend } from '../lib/send'
import { loadTurnstile, renderWidget, type TurnstileHandle } from '../lib/turnstile'

const router = useRouter()
const state = sendState()

const info = ref<BootstrapInfo | null>(null)
const turnstileBox = ref<HTMLElement | null>(null)
let widget: TurnstileHandle | null = null

// nothing staged means a refresh or a direct link: there is no draft to
// send, go home rather than pretend
if (state.phase === 'idle') {
  router.replace('/')
}

// the whole run is observable through the store, the view only reacts
watch(
  () => state.phase,
  (phase) => {
    if (phase === 'done') router.replace({ path: '/uploaded', query: { s: state.shareId } })
  },
)

// the challenge is the gate to start. enforced shares begin only once a
// token lands, everything else starts immediately
onMounted(() => {
  // a fresh bootstrap reconciles enforcement: the form may have staged
  // the run before the server flipped its mode, and the widget needs the
  // site key regardless
  void bootstrap()
    .then((i) => {
      info.value = i
      state.enforced = i.turnstile.enforced
      if (sendStarted()) {
        return
      }
      if (state.phase === 'needs-token' && !state.enforced) {
        void startSend(i, '')
      } else if (state.phase === 'sending' && state.enforced) {
        state.phase = 'needs-token'
      } else if (state.phase === 'sending') {
        void startSend(i, '')
      }
    })
    .catch((e) => {
      state.phase = 'error'
      state.error = `cannot reach the server: ${(e as Error).message}`
    })
  // a done store means this view was revisited after success, the
  // success page is where that visitor belongs
  if (state.phase === 'done') router.replace({ path: '/uploaded', query: { s: state.shareId } })
  // focus sits on the card, not an input, so the escape key is heard at
  // the window level
  window.addEventListener('keydown', onKey)
})

watch(
  [() => state.phase, () => info.value?.turnstile.site_key] as const,
  ([phase, siteKey]) => {
    if (widget) {
      widget.remove()
      widget = null
    }
    if (phase !== 'needs-token' || !siteKey) return
    const isEnforced = state.enforced
    if (!isEnforced) return
    void loadTurnstile()
      .then(() => {
        if (!turnstileBox.value || state.phase !== 'needs-token') return
        widget = renderWidget(turnstileBox.value, siteKey, {
          onToken: (t) => {
            if (state.phase === 'needs-token' && info.value) void startSend(info.value, t)
          },
          onExpire: () => widget?.reset(),
        })
      })
      .catch((e) => {
        state.phase = 'error'
        state.error = `cannot load the human check: ${(e as Error).message}`
      })
  },
  { immediate: true },
)

const snippet = computed(() => {
  const body = state.draft?.body?.trim() ?? ''
  if (body === '') return null
  const firstLine = body.split('\n').find((l) => l.trim() !== '') ?? ''
  return firstLine.length > 140 ? `${firstLine.slice(0, 140)}…` : firstLine
})

const parts = computed(() => ({
  done: state.perFile.reduce((n, f) => n + f.sentParts, 0),
  total: state.perFile.reduce((n, f) => n + f.totalParts, 0),
}))
const pct = computed(() =>
  parts.value.total === 0 ? 0 : Math.round((parts.value.done / parts.value.total) * 100),
)

function filePct(f: { sentParts: number; totalParts: number }): number {
  return f.totalParts === 0 ? 0 : Math.round((f.sentParts / f.totalParts) * 100)
}

function fmtSize(n: number): string {
  if (n >= 1 << 20) return `${(n / (1 << 20)).toFixed(1)} MB`
  if (n >= 1 << 10) return `${(n / (1 << 10)).toFixed(0)} KB`
  return `${n} B`
}

function goHome() {
  cancelSend()
  router.push('/')
}

function retry() {
  if (!info.value) return
  // a spent or absent token is replaced by the fresh widget round
  retrySend(info.value)
}

function onKey(ev: KeyboardEvent) {
  if (ev.key === 'Escape' && state.phase !== 'done') goHome()
}

// leaving mid upload cancels it, the same as the old form closing did
onBeforeRouteLeave(() => {
  if (state.phase === 'sending' || state.phase === 'needs-token') cancelSend()
})
onUnmounted(() => {
  window.removeEventListener('keydown', onKey)
  if (state.phase === 'sending' || state.phase === 'needs-token') cancelSend()
  widget?.remove()
  widget = null
})
</script>

<template>
  <div class="stage" @keydown="onKey">
    <div class="card" :class="{ narrow: state.phase === 'needs-token' }">
      <header class="head">
        <h2>
          <span v-if="state.phase === 'needs-token'" class="head-step">Ready to send</span>
          <span v-else-if="state.phase === 'error'">Could not send</span>
          <span v-else>Sending your share</span>
        </h2>
        <p v-if="state.phase === 'needs-token'" class="sub">One quick human check, then the upload starts.</p>
        <p v-else-if="state.phase === 'error'" class="sub">
          Nothing was lost on your side. You can try again.
        </p>
        <p v-else class="sub">Keep this tab open, your files are on their way.</p>
      </header>

      <div class="recap">
        <p class="recap-title">{{ state.draft?.title }}</p>
        <p v-if="snippet" class="recap-snippet">{{ snippet }}</p>
      </div>

      <p v-if="state.phase === 'error'" class="error" role="alert">{{ state.error }}</p>

      <div v-if="state.phase === 'needs-token'" ref="turnstileBox" class="ts-box"></div>

      <ul v-if="state.perFile.length" class="files" :aria-busy="state.phase === 'sending'">
        <li v-for="(f, i) in state.perFile" :key="i" :class="{ done: f.sentParts >= f.totalParts }">
          <span class="file-icon" aria-hidden="true">
            <svg
              v-if="f.sentParts >= f.totalParts && state.phase !== 'needs-token'"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
              stroke-linecap="round"
              stroke-linejoin="round"
            >
              <path d="M20 6L9 17l-5-5" />
            </svg>
            <svg
              v-else
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="1.5"
              stroke-linecap="round"
              stroke-linejoin="round"
            >
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
              <polyline points="14 2 14 8 20 8" />
            </svg>
          </span>
          <span class="file-meta">
            <span class="name">{{ f.name }}</span>
            <span class="size">{{ fmtSize(f.size) }}</span>
          </span>
          <span class="file-track" aria-hidden="true">
            <span class="file-fill" :style="{ width: `${filePct(f)}%` }"></span>
          </span>
        </li>
      </ul>

      <div v-if="state.phase === 'sending'" class="overall" role="status">
        <div class="track">
          <div class="fill" :style="{ width: `${pct}%` }"></div>
        </div>
        <span class="overall-label">{{ parts.done }} / {{ parts.total }} parts</span>
      </div>

      <div class="tray">
        <button
          v-if="state.phase === 'sending' || state.phase === 'needs-token'"
          type="button"
          class="btn-ghost"
          @click="goHome()"
        >
          Cancel
        </button>
        <template v-if="state.phase === 'error'">
          <button type="button" class="btn-primary" @click="retry()">Try again</button>
          <button type="button" class="btn-ghost" @click="goHome()">Back</button>
        </template>
      </div>
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
  gap: 1.2rem;
}

/* shares the morph name with the composer card and the success card, the
   three views grow out of one another */
.card {
  view-transition-name: page-card;
  width: min(34rem, calc(100vw - 2rem));
  background: var(--card);
  border: 1px solid var(--outline-soft);
  border-radius: 16px;
  padding: 2rem;
  box-shadow: 0 20px 48px rgba(52, 71, 97, 0.12);
  display: flex;
  flex-direction: column;
  gap: 1.4rem;
}

.card.narrow {
  width: min(26rem, calc(100vw - 2rem));
}

.head h2 {
  font-family: var(--font-display);
  color: var(--heading);
  font-size: 1.5rem;
  margin: 0;
}

.sub {
  margin: 0.4rem 0 0;
  color: var(--body);
  font-size: 0.92rem;
}

.recap {
  border-left: 3px solid var(--accent);
  padding: 0.35rem 0 0.35rem 0.9rem;
}

.recap-title {
  margin: 0;
  color: var(--heading);
  font-weight: 600;
  overflow-wrap: anywhere;
}

.recap-snippet {
  margin: 0.25rem 0 0;
  color: var(--body);
  font-size: 0.88rem;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
  overflow-wrap: anywhere;
}

.error {
  color: var(--danger, #b3261e);
  background: rgba(179, 38, 30, 0.07);
  border-radius: 8px;
  padding: 0.7rem 0.9rem;
  margin: 0;
  font-size: 0.88rem;
  overflow-wrap: anywhere;
}

.ts-box {
  display: flex;
  justify-content: center;
  min-height: 65px;
}

.files {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.55rem;
}

.files li {
  display: grid;
  grid-template-columns: 1.6rem 1fr auto;
  align-items: center;
  gap: 0.7rem;
}

.files li.done .file-icon {
  color: var(--accent);
}

.file-icon {
  color: var(--body);
  display: flex;
}

.file-icon svg {
  width: 1.35rem;
  height: 1.35rem;
}

.file-meta {
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.name {
  color: var(--heading);
  font-size: 0.9rem;
  font-weight: 500;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.size {
  color: var(--body);
  font-size: 0.78rem;
}

.file-track {
  width: 5.5rem;
  height: 4px;
  border-radius: 9999px;
  background: var(--outline-soft);
  overflow: hidden;
}

.file-fill {
  display: block;
  height: 100%;
  border-radius: 9999px;
  background: var(--accent);
  transition: width 240ms ease;
}

.files li.done .file-fill {
  background: var(--accent);
}

.overall {
  display: flex;
  align-items: center;
  gap: 0.8rem;
}

.track {
  flex: 1;
  height: 6px;
  border-radius: 9999px;
  background: var(--outline-soft);
  overflow: hidden;
}

.fill {
  height: 100%;
  border-radius: 9999px;
  background: var(--accent);
  transition: width 240ms ease;
}

.overall-label {
  color: var(--body);
  font-size: 0.8rem;
  white-space: nowrap;
}

.tray {
  display: flex;
  justify-content: flex-end;
  gap: 0.6rem;
}

@media (prefers-reduced-motion: reduce) {
  .file-fill,
  .fill {
    transition: none;
  }
}
</style>
