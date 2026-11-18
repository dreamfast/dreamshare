<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute } from 'vue-router'
import { buildThemedQr } from '../lib/qr'

const route = useRoute()
const handoff = (() => {
  // per share slot, and it is consumed on read: the key dies with the page
  // rather than living in storage for the tab's whole life
  const sid = String(route.query.s ?? '')
  if (!sid) return null
  try {
    const raw = sessionStorage.getItem(`dreamshare.handoff.v1.${sid}`)
    if (raw) {
      sessionStorage.removeItem(`dreamshare.handoff.v1.${sid}`)
      return JSON.parse(raw) as { s: string; k: string; m: string }
    }
  } catch {
    // fall through to the honest no key state
  }
  return null
})()
// the share id may arrive by url, the key and manager token only through
// session storage, the url carries nothing secret
const shareID = computed(() => handoff?.s ?? String(route.query.s ?? ''))
const fragment = computed(() => handoff?.k ?? '')
const managerToken = computed(() => handoff?.m ?? '')
const secretLost = computed(() => shareID.value !== '' && fragment.value === '')
const copied = ref(false)
const copiedRevoke = ref(false)

const link = computed(() => `${location.origin}/s/${shareID.value}#${fragment.value}`)
const linkBase = computed(() => `${location.origin}/s/${shareID.value}`)
const managerLink = computed(() => `${location.origin}/m/${managerToken.value}`)

// rendered entirely in the browser, the fragment never leaves the page,
// error correction H keeps it scannable under the centre logo pad
const qrSvg = computed(() => {
  if (!link.value) return ''
  try {
    return buildThemedQr(link.value)
  } catch {
    // a too long link simply renders no qr, copy still works
    return ''
  }
})

async function copy(text: string, which: 'link' | 'revoke') {
  try {
    await navigator.clipboard.writeText(text)
    if (which === 'link') {
      copied.value = true
      setTimeout(() => (copied.value = false), 1500)
    } else {
      copiedRevoke.value = true
      setTimeout(() => (copiedRevoke.value = false), 1500)
    }
  } catch {
    // clipboard needs a gesture or permission, the code block below is the
    // manual fallback
  }
}
</script>

<template>
  <section class="done">
    <div v-if="secretLost" class="card state-card error-card" role="alert">
      <span class="state-icon" aria-hidden="true">
        <svg
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="1.8"
          stroke-linecap="round"
          stroke-linejoin="round"
        >
          <circle cx="12" cy="12" r="10" />
          <line x1="12" y1="8" x2="12" y2="12" />
          <line x1="12" y1="16" x2="12.01" y2="16" />
        </svg>
      </span>
      <div>
        <p class="state-title">The link is not in this tab any more</p>
        <p class="state-body">It is shown once after the upload. A new tab or window cannot recover it.</p>
      </div>
    </div>

    <template v-else>
      <div class="card page">
        <!-- success header, icon beside the words -->
        <div class="head">
          <span class="head-icon" aria-hidden="true">
            <svg
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="1.8"
              stroke-linecap="round"
              stroke-linejoin="round"
            >
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
              <polyline points="17 8 12 3 7 8" />
              <line x1="12" y1="3" x2="12" y2="15" />
            </svg>
          </span>
          <div>
            <h1>Your share is ready</h1>
            <p class="head-sub">
              Send the link below to whoever needs the files. It wipes itself after download or at expiry.
            </p>
          </div>
        </div>

        <!-- the link is the key warning, a calm accent bar -->
        <div class="warn" role="alert">
          <p>
            The link is the key. Anyone holding it can open the share, and if you lose it nobody can recover
            the files, including us.
          </p>
        </div>

        <!-- the link itself -->
        <div class="link-section">
          <div class="link-labels">
            <span class="link-label">Share link</span>
            <span class="link-hint">
              The part after # is your encryption key. We never see it, and we cannot see your files. Only
              those you share the key with can open them.
            </span>
          </div>
          <code class="link"
            ><span class="link-base">{{ linkBase }}</span
            ><span class="link-frag">#{{ fragment }}</span></code
          >
          <div class="copy-row">
            <button type="button" class="btn-primary" @click="copy(link, 'link')">
              {{ copied ? 'Copied' : 'Copy link' }}
            </button>
            <span v-if="copied" class="copy-feedback" aria-live="polite">Copied to clipboard</span>
          </div>
        </div>

        <!-- qr on the left, plain words on the right -->
        <div v-if="qrSvg" class="qr-box">
          <div class="qr" v-html="qrSvg" />
          <div class="qr-text">
            <p class="qr-title">Scan to open on a phone</p>
            <p class="qr-sub">Point the camera at the code, the key is inside it.</p>
          </div>
        </div>

        <details v-if="managerLink" class="revoke">
          <summary>Need to cancel this share later? Keep the revoke link</summary>
          <div class="revoke-body">
            <code class="link">{{ managerLink }}</code>
            <button type="button" class="btn-ghost" @click="copy(managerLink, 'revoke')">
              {{ copiedRevoke ? 'Copied' : 'Copy' }}
            </button>
          </div>
        </details>

        <div class="end-actions">
          <RouterLink to="/" class="btn-ghost">Share another</RouterLink>
          <RouterLink to="/mine" class="btn-ghost">My shares</RouterLink>
        </div>
      </div>
    </template>
  </section>
</template>

<style scoped>
.done {
  max-width: 44rem;
  margin: 2.5rem auto;
  padding: 0 1rem;
}

.page {
  view-transition-name: page-card;
  padding: 1.75rem 2rem;
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

/* success header */
.head {
  display: flex;
  gap: 1rem;
  align-items: flex-start;
}

.head-icon {
  display: flex;
  width: 3rem;
  height: 3rem;
  border-radius: 12px;
  background: var(--surface-mid);
  color: var(--accent-deep);
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  box-shadow: 0 4px 12px rgba(92, 153, 238, 0.15);
}

.head-icon svg {
  width: 1.4rem;
  height: 1.4rem;
}

h1 {
  font-size: 24px;
  margin: 0 0 0.25rem;
}

.head-sub {
  margin: 0;
  font-size: 14px;
  color: var(--on-surface-variant);
}

/* warning, accent bar on the left */
.warn {
  border-left: 4px solid var(--warn-bar);
  background: var(--warn-soft);
  border-radius: 0 10px 10px 0;
  padding: 0.8rem 1rem;
}

.warn p {
  margin: 0;
  font-size: 13px;
  line-height: 20px;
  font-weight: 500;
  color: #7a3d00;
}

/* link section */
.link-section {
  display: flex;
  flex-direction: column;
  gap: 0.6rem;
}

.link-labels {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 1rem;
  flex-wrap: wrap;
}

.link-label {
  font-size: 12px;
  font-weight: 500;
  letter-spacing: 0.8px;
  text-transform: uppercase;
  color: var(--on-surface-variant);
}

.link-hint {
  font-size: 12px;
  line-height: 18px;
  color: var(--on-surface-variant);
  opacity: 0.8;
  max-width: 22rem;
  text-align: right;
}

@media (max-width: 640px) {
  .link-hint {
    text-align: left;
  }
}

.link {
  display: block;
  overflow-wrap: anywhere;
  padding: 12px 14px;
  background: var(--surface-low);
  border-radius: 10px;
  font-family: var(--mono);
  font-size: 13px;
  line-height: 20px;
  color: var(--on-surface);
  user-select: all;
  box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.02);
}

.link-frag {
  color: var(--accent-deep);
  font-weight: 500;
}

.copy-row {
  display: flex;
  align-items: center;
  gap: 0.9rem;
  flex-wrap: wrap;
}

.copy-feedback {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  font-size: 13px;
  color: var(--good);
}

/* qr row */
.qr-box {
  display: flex;
  gap: 1.5rem;
  align-items: center;
  background: rgba(238, 244, 255, 0.7);
  border-radius: 12px;
  padding: 1.25rem;
  flex-wrap: wrap;
}

.qr {
  background: #fff;
  padding: 0.6rem;
  border-radius: 10px;
  box-shadow: 0 2px 8px rgba(52, 71, 97, 0.08);
  flex-shrink: 0;
}

.qr :deep(svg) {
  display: block;
  width: 132px;
  height: 132px;
}

.qr-title {
  margin: 0 0 0.25rem;
  font-family: 'Questrial', sans-serif;
  font-size: 17px;
  color: var(--on-surface);
}

.qr-sub {
  margin: 0;
  font-size: 13px;
  color: var(--on-surface-variant);
}

/* revoke */
.revoke summary {
  cursor: pointer;
  font-size: 13px;
  font-weight: 500;
  color: var(--on-surface-variant);
  user-select: none;
}

.revoke summary:hover {
  color: var(--accent-deep);
}

.revoke-body {
  display: flex;
  gap: 0.75rem;
  align-items: stretch;
  margin-top: 0.7rem;
  flex-wrap: wrap;
}

.revoke-body .link {
  flex: 1;
  min-width: 14rem;
}

.end-actions {
  display: flex;
  gap: 0.75rem;
  justify-content: center;
  border-top: 1px solid var(--outline-soft);
  padding-top: 1.25rem;
}

/* secret lost state */
.state-card {
  view-transition-name: page-card;
  padding: 1.25rem 1.4rem;
  display: flex;
  gap: 1rem;
  align-items: center;
}

.state-icon {
  display: flex;
  width: 2.75rem;
  height: 2.75rem;
  border-radius: 12px;
  background: var(--error-soft);
  color: var(--error);
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.state-icon svg {
  width: 1.3rem;
  height: 1.3rem;
}

.state-title {
  margin: 0 0 0.2rem;
  font-family: 'Questrial', sans-serif;
  font-size: 19px;
  color: var(--on-surface);
}

.state-body {
  margin: 0;
  font-size: 13px;
  color: var(--on-surface-variant);
}

.error-card {
  background: var(--error-soft);
  border-color: rgba(186, 26, 26, 0.2);
}

@media (max-width: 640px) {
  .page {
    padding: 1.25rem;
  }
}
</style>
