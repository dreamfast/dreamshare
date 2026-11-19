<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import {
  bootstrap,
  shareMeta,
  fetchCheck,
  downloadFile,
  ackFile,
  notifyDownloaded,
  csrfCookie,
  type ShareMeta,
} from '../lib/api'
import { decodeFragmentKey, openStream, deriveSubkey, subkeyInfo } from '../crypto/frame'
import { openManifest, tryCheck, type Manifest, type ManifestFile } from '../lib/manifest'
import { renderBody } from '../lib/markdown'
import { safeName } from '../lib/safename'

const route = useRoute()
const token = computed(() => String(route.params.token ?? ''))

const state = ref<'loading' | 'badkey' | 'gone' | 'error' | 'ready' | 'wiped'>('loading')
const errorMsg = ref('')
const meta = ref<ShareMeta | null>(null)
const manifest = ref<Manifest | null>(null)
const fileStates = ref<Record<string, 'idle' | 'downloading' | 'verifying' | 'verified' | 'failed'>>({})
const previews = ref<Record<string, string>>({})
const bodyHtml = ref('')

let masterKey: Uint8Array | null = null

// display names lose control and bidi override characters, the fake.jpg.exe
// direction trick lives there

onMounted(async () => {
  try {
    const fragment = decodeURIComponent(location.hash.replace(/^#/, ''))
    masterKey = decodeFragmentKey(fragment)
  } catch {
    state.value = 'badkey'
    return
  }
  try {
    // the ack and notify mutations need the csrf pair, mint it up front
    await bootstrap()
    meta.value = await shareMeta(token.value)
    if (meta.value.status !== 'active') {
      state.value = 'gone'
      return
    }
    const checkCt = await fetchCheck(token.value)
    if (checkCt && !(await tryCheck(masterKey, token.value, checkCt))) {
      state.value = 'badkey'
      return
    }
    // the manifest arrives as its own fetch once decryptable, here it is
    // embedded in the share metadata response for v1
    const resp = await fetch(`/api/shares/${token.value}/manifest`)
    if (!resp.ok) {
      errorMsg.value = 'manifest missing'
      state.value = 'error'
      return
    }
    const manifestCt = new Uint8Array(await resp.arrayBuffer())
    manifest.value = await openManifest(masterKey, token.value, manifestCt)
    bodyHtml.value = renderBody(manifest.value.body ?? '')
    for (const f of manifest.value.files) {
      fileStates.value[f.id] = 'idle'
      if (f.mime.startsWith('image/') && f.size <= 8 * 1024 * 1024) {
        try {
          const subkey = await deriveSubkey(masterKey, subkeyInfo('file', f.id))
          const ct = await downloadFile(token.value, f.id)
          const plain = await openStream(subkey, ct, 0n, token.value, 'file')
          previews.value[f.id] = URL.createObjectURL(new Blob([plain.slice().buffer], { type: f.mime }))
        } catch {
          // a preview is best effort, the download button still works
        }
      }
    }
    state.value = 'ready'
  } catch (e) {
    const msg = (e as Error).message
    if (msg === 'not_found' || msg === 'gone' || msg.startsWith('http_4') || msg.startsWith('http_5')) {
      state.value = 'gone'
    } else {
      errorMsg.value = msg
      state.value = 'error'
    }
  }
})

async function download(f: ManifestFile) {
  if (!masterKey) return
  fileStates.value[f.id] = 'downloading'
  try {
    const subkey = await deriveSubkey(masterKey, subkeyInfo('file', f.id))
    const ct = await downloadFile(token.value, f.id)
    fileStates.value[f.id] = 'verifying'
    const plain = await openStream(subkey, ct, 0n, token.value, 'file')
    const digest = await crypto.subtle.digest('SHA-256', plain.buffer as ArrayBuffer)
    const hex = Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
    if (hex !== f.sha256) {
      fileStates.value[f.id] = 'failed'
      return
    }
    fileStates.value[f.id] = 'verified'
    const blob = new Blob([plain.buffer as ArrayBuffer], { type: f.mime })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = safeName(f.name)
    a.click()
    // give the engine a beat before revoking, an immediate revoke can cut
    // the save short on some engines
    setTimeout(() => URL.revokeObjectURL(url), 30_000)
    await ackFile(csrfCookie(), token.value, f.id)
    await notify()
    maybeWiped()
  } catch {
    fileStates.value[f.id] = 'failed'
  }
}

async function confirmBody() {
  await ackFile(csrfCookie(), token.value, null)
  await notify()
  maybeWiped()
}

function maybeWiped() {
  const allVerified = (manifest.value?.files ?? []).every((f) => fileStates.value[f.id] === 'verified')
  if (allVerified && manifest.value && manifest.value.files.length > 0) {
    if (meta.value?.expiry_mode === 'burn_on_ack') state.value = 'wiped'
  }
  if (manifest.value && manifest.value.files.length === 0 && meta.value?.expiry_mode === 'burn_on_ack') {
    state.value = 'wiped'
  }
}

async function notify() {
  const to = manifest.value?.notify_email
  if (!to) return
  try {
    await notifyDownloaded(csrfCookie(), token.value, to)
  } catch {
    // best effort by design
  }
}

const humanBytes = (n: number) =>
  n > 1024 * 1024 ? `${(n / 1024 / 1024).toFixed(1)} MiB` : `${Math.max(1, Math.round(n / 1024))} KiB`

const totalSize = computed(() => (manifest.value?.files ?? []).reduce((n, f) => n + f.size, 0))
</script>

<template>
  <section class="share">
    <!-- opening -->
    <div v-if="state === 'loading'" class="card state-card opening">
      <span class="spinner" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round">
          <path d="M21 12a9 9 0 1 1-9-9" />
        </svg>
      </span>
      <h2>Opening…</h2>
      <p class="state-body">Decrypting in your browser, nothing readable travels.</p>
    </div>

    <!-- problem states -->
    <div v-else-if="state === 'badkey'" class="card state-card" role="alert">
      <span class="state-icon warn-icon" aria-hidden="true">
        <svg
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="1.8"
          stroke-linecap="round"
          stroke-linejoin="round"
        >
          <path d="M14.5 9.5 8 16l-4 4 4-1 6.5-6.5" />
          <circle cx="16" cy="8" r="3" />
        </svg>
      </span>
      <div>
        <h2 class="state-heading">This link is incomplete</h2>
        <p class="state-body">
          Ask the sender for the full link. The part after the
          <code class="hash">#</code> matters, it is the key and it never reaches any server.
        </p>
      </div>
    </div>
    <div v-else-if="state === 'gone'" class="card state-card" role="alert">
      <span class="state-icon gone-icon" aria-hidden="true">
        <svg
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="1.8"
          stroke-linecap="round"
          stroke-linejoin="round"
        >
          <rect x="4" y="11" width="16" height="10" rx="2" />
          <path d="M8 11V7a4 4 0 0 1 8 0v4" />
        </svg>
      </span>
      <div>
        <h2 class="state-heading">This share is no longer available</h2>
        <p class="state-body">It was opened, revoked, or expired.</p>
      </div>
    </div>
    <div v-else-if="state === 'error'" class="card state-card" role="alert">
      <span class="state-icon warn-icon" aria-hidden="true">
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
        <h2 class="state-heading">Something went wrong</h2>
        <p class="state-body">{{ errorMsg }}</p>
      </div>
    </div>

    <template v-else-if="state === 'ready' || state === 'wiped'">
      <div class="card page">
        <h1>{{ manifest?.title }}</h1>

        <!-- the one sanctioned html sink, sanitised output only -->
        <div v-if="bodyHtml" class="body markdown" v-html="bodyHtml" />

        <div v-if="state === 'wiped'" class="wiped" role="status">
          <span class="wiped-icon" aria-hidden="true">
            <svg
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
              stroke-linecap="round"
              stroke-linejoin="round"
            >
              <path d="M20 6L9 17l-5-5" />
            </svg>
          </span>
          <p>Every file was verified and the share wiped itself. This link no longer works.</p>
        </div>

        <div v-if="manifest?.files.length" class="files-section">
          <div class="files-head">
            <h2 class="files-title">
              Files
              <span class="count-pill">{{ manifest.files.length }}</span>
            </h2>
            <span class="files-total">{{ humanBytes(totalSize) }} total</span>
          </div>

          <ul class="files">
            <li v-for="f in manifest!.files" :key="f.id" class="file-row">
              <span class="thumb-wrap">
                <img v-if="previews[f.id]" :src="previews[f.id]" :alt="safeName(f.name)" class="thumb" />
                <span v-else class="file-icon" aria-hidden="true">
                  <svg
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
              </span>
              <span class="file-meta">
                <span class="name-row">
                  <span class="name">{{ safeName(f.name) }}</span>
                  <span class="size-chip">{{ humanBytes(f.size) }}</span>
                </span>
                <span class="hash-row">
                  <span class="hash-label">SHA-256</span>
                  <span class="hash">{{ f.sha256.slice(0, 16) }}…</span>
                </span>
              </span>
              <button
                type="button"
                class="dl"
                :class="{
                  good: fileStates[f.id] === 'verified',
                  warn: fileStates[f.id] === 'failed',
                }"
                :disabled="
                  fileStates[f.id] === 'downloading' || fileStates[f.id] === 'verifying' || state === 'wiped'
                "
                @click="download(f)"
              >
                <svg
                  v-if="fileStates[f.id] === 'verified'"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="2"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  aria-hidden="true"
                >
                  <path d="M20 6L9 17l-5-5" />
                </svg>
                <svg
                  v-else-if="fileStates[f.id] !== 'downloading' && fileStates[f.id] !== 'verifying'"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="2"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  aria-hidden="true"
                >
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                  <polyline points="7 10 12 15 17 10" />
                  <line x1="12" y1="15" x2="12" y2="3" />
                </svg>
                <span v-else class="dl-spin" aria-hidden="true"></span>
                <template v-if="fileStates[f.id] === 'verified'">Verified</template>
                <template v-else-if="fileStates[f.id] === 'downloading'">Fetching…</template>
                <template v-else-if="fileStates[f.id] === 'verifying'">Verifying…</template>
                <template v-else-if="fileStates[f.id] === 'failed'">Failed, retry</template>
                <template v-else>Download</template>
              </button>
            </li>
          </ul>
        </div>

        <p v-if="manifest && manifest.files.length === 0 && state === 'ready'" class="confirm">
          <button type="button" class="btn-primary" @click="confirmBody">
            I have read this, wipe the share
          </button>
        </p>
      </div>
    </template>
  </section>
</template>

<style scoped>
.share {
  max-width: 44rem;
  margin: 2rem auto;
  padding: 0 1rem;
}

/* state cards */
.state-card {
  view-transition-name: page-card;
  padding: 1.75rem;
  display: flex;
  gap: 1.1rem;
  align-items: flex-start;
}

.state-card.opening {
  flex-direction: column;
  align-items: center;
  text-align: center;
  padding: 3rem 2rem;
}

.state-heading,
h2 {
  font-family: 'Questrial', sans-serif;
  font-size: 22px;
  color: var(--on-surface);
  margin: 0 0 0.4rem;
}

.state-body {
  margin: 0;
  font-size: 14px;
  line-height: 22px;
  color: var(--on-surface-variant);
}

.state-icon {
  display: flex;
  width: 3rem;
  height: 3rem;
  border-radius: 12px;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.state-icon svg {
  width: 1.4rem;
  height: 1.4rem;
}

.warn-icon {
  background: var(--warn-soft);
  color: #a84201;
}

.gone-icon {
  background: var(--surface-mid);
  color: var(--on-surface-variant);
}

.hash {
  font-family: var(--mono);
  font-size: 12px;
  background: var(--surface-mid);
  color: var(--accent-deep);
  border-radius: 4px;
  padding: 1px 5px;
}

.spinner {
  display: inline-flex;
  width: 3.2rem;
  height: 3.2rem;
  border-radius: 50%;
  background: var(--surface-low);
  color: var(--accent);
  align-items: center;
  justify-content: center;
  animation: spin 1s linear infinite;
  margin-bottom: 0.4rem;
}

.spinner svg {
  width: 1.5rem;
  height: 1.5rem;
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

/* the ready page */
.page {
  view-transition-name: page-card;
  padding: 1.75rem 2rem;
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

h1 {
  font-size: 26px;
  margin: 0;
}

/* markdown body, blockquotes get the designer accent bar */
.body {
  font-size: 14px;
  line-height: 24px;
  color: var(--on-surface-variant);
}

.body :deep(blockquote) {
  margin: 0.75rem 0;
  padding: 0.5rem 1rem;
  border-left: 4px solid var(--accent);
  background: rgba(238, 244, 255, 0.5);
  border-radius: 0 10px 10px 0;
  font-style: italic;
  color: var(--on-surface-variant);
}

.body :deep(p) {
  margin: 0.5rem 0;
}

.body :deep(ul) {
  padding-left: 1.25rem;
  margin: 0.5rem 0;
}

.body :deep(a) {
  overflow-wrap: anywhere;
}

.body :deep(pre) {
  overflow-x: auto;
}

/* wiped banner */
.wiped {
  display: flex;
  gap: 0.85rem;
  align-items: center;
  background: var(--good-soft);
  border: 1px solid rgba(30, 122, 70, 0.2);
  border-radius: 12px;
  padding: 1rem 1.25rem;
}

.wiped-icon {
  display: flex;
  width: 2.25rem;
  height: 2.25rem;
  border-radius: 50%;
  background: var(--good);
  color: #fff;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.wiped-icon svg {
  width: 1.1rem;
  height: 1.1rem;
}

.wiped p {
  margin: 0;
  font-size: 14px;
  color: var(--on-surface);
}

/* files section */
.files-head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 1rem;
  margin-bottom: 0.85rem;
}

.files-title {
  font-size: 17px;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.count-pill {
  font-family: 'Roboto', system-ui, sans-serif;
  font-size: 11px;
  font-weight: 600;
  background: rgba(92, 153, 238, 0.12);
  color: var(--accent-deep);
  border-radius: 9999px;
  padding: 2px 9px;
}

.files-total {
  font-size: 12px;
  color: var(--on-surface-variant);
}

.files {
  list-style: none;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 0.6rem;
}

.file-row {
  display: flex;
  gap: 0.9rem;
  align-items: center;
  padding: 0.85rem 1rem;
  border-radius: 12px;
  background: var(--surface-low);
  transition: background 0.2s;
}

.file-row:hover {
  background: var(--surface-mid);
}

.thumb-wrap {
  width: 3rem;
  height: 3rem;
  border-radius: 10px;
  overflow: hidden;
  flex-shrink: 0;
}

.thumb {
  width: 100%;
  height: 100%;
  object-fit: cover;
  display: block;
}

.file-icon {
  display: flex;
  width: 100%;
  height: 100%;
  background: var(--card);
  color: var(--accent-deep);
  align-items: center;
  justify-content: center;
}

.file-icon svg {
  width: 1.2rem;
  height: 1.2rem;
}

.file-meta {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 0.2rem;
}

.name-row {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  flex-wrap: wrap;
  min-width: 0;
}

.name {
  font-weight: 500;
  font-size: 14px;
  overflow-wrap: anywhere;
}

.size-chip {
  font-family: var(--mono);
  font-size: 11px;
  background: var(--card);
  color: var(--on-surface-variant);
  border-radius: 6px;
  padding: 1px 7px;
}

.hash-row {
  display: flex;
  align-items: center;
  gap: 0.45rem;
  font-family: var(--mono);
  font-size: 11px;
  min-width: 0;
}

.hash-label {
  color: var(--on-surface-variant);
}

.hash {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.dl {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  border: none;
  background: var(--accent);
  color: var(--on-accent);
  border-radius: 8px;
  padding: 10px 18px;
  font-size: 13px;
  font-weight: 500;
  letter-spacing: 0.6px;
  cursor: pointer;
  transition:
    background 0.2s,
    color 0.2s;
  flex-shrink: 0;
}

.dl svg {
  width: 1rem;
  height: 1rem;
}

.dl:hover:not(:disabled) {
  background: var(--accent-deep);
}

.dl:disabled {
  opacity: 0.5;
  cursor: default;
}

.dl.good {
  background: var(--good-soft);
  color: var(--good);
}

.dl.good:hover:not(:disabled) {
  background: #d4eddd;
}

.dl.warn {
  background: var(--error-soft);
  color: var(--error);
}

.dl-spin {
  width: 0.9rem;
  height: 0.9rem;
  border-radius: 50%;
  border: 2px solid rgba(255, 255, 255, 0.4);
  border-top-color: #fff;
  animation: spin 0.8s linear infinite;
}

.confirm {
  text-align: center;
  margin: 0;
}

@media (max-width: 640px) {
  .page {
    padding: 1.25rem;
  }

  .file-row {
    flex-wrap: wrap;
  }

  .dl {
    width: 100%;
    order: 3;
  }
}
</style>
