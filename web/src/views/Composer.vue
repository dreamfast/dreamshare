<script setup lang="ts">
// The home page and the upload form are one morphing element in the
// DreamFast brand colours.
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  csrfCookie,
  bootstrap,
  createShare,
  putPart,
  completeSession,
  finalizeShare,
  type BootstrapInfo,
} from '../lib/api'
import { planParts, sealPart, startingIndex, freshNoncePrefix, ciphertextSize } from '../lib/pipeline'
import { generateMasterKey, encodeFragmentKey } from '../crypto/frame'
import { sealManifest, toB64, type ManifestFile } from '../lib/manifest'
import { saveMineRecord } from '../lib/mine'
import { loadTurnstile, renderWidget, type TurnstileHandle } from '../lib/turnstile'

const route = useRoute()
const router = useRouter()

const open = computed(() => route.path === '/upload')
const info = ref<BootstrapInfo | null>(null)
const files = ref<File[]>([])
const title = ref('')
const body = ref('')
const notifyEmail = ref('')
const expiryMode = ref<'burn_on_ack' | 'ttl'>('burn_on_ack')
const expiryDays = ref(1)
const busy = ref(false)
const error = ref('')
const progress = ref({ done: 0, total: 0 })
const dragOver = ref(false)
const fileInput = ref<HTMLInputElement | null>(null)
const titleInput = ref<HTMLInputElement | null>(null)

// the challenge widget, only mounted when the server enforces it
const turnstileBox = ref<HTMLElement | null>(null)
const turnstileToken = ref('')
let widget: TurnstileHandle | null = null

onMounted(async () => {
  try {
    info.value = await bootstrap()
  } catch (e) {
    error.value = `cannot reach the server: ${(e as Error).message}`
  }
  if (open.value) titleInput.value?.focus()
})

watch(open, (v) => {
  if (v) requestAnimationFrame(() => titleInput.value?.focus())
})

// the widget lives and dies with the open form, the third-party script is
// only fetched at all when the challenge is enforced
watch(
  () => [open.value, turnstileEnforced.value, info.value?.turnstile.site_key] as const,
  ([isOpen, enforced, siteKey]) => {
    if (widget) {
      widget.remove()
      widget = null
      turnstileToken.value = ''
    }
    if (!isOpen || !enforced || !siteKey) return
    void loadTurnstile()
      .then(() => {
        if (!turnstileBox.value) return
        widget = renderWidget(turnstileBox.value, siteKey, {
          onToken: (t) => (turnstileToken.value = t),
          onExpire: () => (turnstileToken.value = ''),
        })
      })
      .catch((e) => {
        error.value = `cannot load the human check: ${(e as Error).message}`
      })
  },
  { immediate: true },
)

function toggle() {
  if (busy.value) return
  if (open.value) {
    router.push('/')
  } else {
    router.push('/upload')
  }
}

function onKey(ev: KeyboardEvent) {
  if (ev.key === 'Escape' && open.value && !busy.value) {
    router.push('/')
    return
  }
  if (ev.key === 'Tab' && open.value) {
    const panel = document.querySelector('.morph.open')
    if (!(panel instanceof HTMLElement)) return
    const focusables = panel.querySelectorAll<HTMLElement>('button, input, textarea, select, a[href]')
    if (focusables.length === 0) return
    const first = focusables[0]!
    const last = focusables[focusables.length - 1]!
    if (ev.shiftKey && document.activeElement === first) {
      ev.preventDefault()
      last.focus()
    } else if (!ev.shiftKey && document.activeElement === last) {
      ev.preventDefault()
      first.focus()
    }
  }
}

const totalBytes = computed(() => files.value.reduce((n, f) => n + f.size, 0))
const tooBig = computed(() => info.value !== null && totalBytes.value > info.value.limits.max_share_bytes)
const tooMany = computed(
  () => info.value !== null && files.value.length > info.value.limits.max_files_per_share,
)
const turnstileEnforced = computed(() => info.value?.turnstile.enforced ?? false)
const turnstileReady = computed(() => !turnstileEnforced.value || turnstileToken.value !== '')
const canSubmit = computed(
  () => !busy.value && title.value.trim() !== '' && !tooBig.value && !tooMany.value && turnstileReady.value,
)
const progressPct = computed(() =>
  progress.value.total === 0 ? 0 : Math.round((progress.value.done / progress.value.total) * 100),
)

function pickFiles(list: FileList | null) {
  if (!list) return
  for (const f of Array.from(list)) {
    if (files.value.length >= (info.value?.limits.max_files_per_share ?? 32)) break
    if (f.size === 0) continue
    files.value.push(f)
  }
}

function onDrop(ev: DragEvent) {
  dragOver.value = false
  pickFiles(ev.dataTransfer?.files ?? null)
}

function removeFile(i: number) {
  files.value.splice(i, 1)
}

async function sha256Hex(buf: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', buf)
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

async function submit() {
  if (!info.value || !canSubmit.value) return
  busy.value = true
  error.value = ''
  try {
    const master = generateMasterKey()
    const fragment = encodeFragmentKey(master)
    const chunk = info.value.limits.chunk_max_bytes
    const csrf = csrfCookie()

    const staged = files.value.map((f) => ({ file: f, parts: planParts(f.size, chunk) }))
    progress.value = { done: 0, total: staged.reduce((n, s) => n + s.parts.length, 0) }

    const created = await createShare(
      csrf,
      {
        files: staged.map((s) => ({
          size: s.parts.reduce((acc, p) => acc + ciphertextSize(p.plaintextLength), 0),
          frame_count: Math.ceil(s.file.size / info.value!.limits.frame_size),
          frame_size: info.value!.limits.frame_size,
          part_size: chunk,
          expected_parts: s.parts.length,
        })),
        expiry_mode: expiryMode.value,
        expiry_days: expiryDays.value,
        notify_wanted: notifyEmail.value.trim() !== '',
      },
      turnstileToken.value,
    )

    // per share slot: a single slot would let a failed later upload
    // destroy the only key copy of an earlier live share
    const handoffKey = `dreamshare.handoff.v1.${created.share_id}`
    try {
      sessionStorage.setItem(
        handoffKey,
        JSON.stringify({ s: created.share_id, k: fragment, m: created.manager_token }),
      )
    } catch (storageErr) {
      error.value = `cannot store the link: ${(storageErr as Error).message}. Nothing was uploaded.`
      return
    }

    const manifestFiles: ManifestFile[] = []
    for (let i = 0; i < staged.length; i++) {
      const entry = staged[i]
      const session = created.upload_sessions[i]
      if (!entry || !session) throw new Error('session_missing')
      const { file, parts } = entry
      const prefix = await freshNoncePrefix()
      const lastNumber = parts[parts.length - 1]?.number ?? 1

      // two parts in flight, the look ahead tokens from each response feed
      // the pool
      const tokenPool: string[] = [...session.first_tokens]
      let nextPart = 1
      let firstError: unknown = null
      const send = async (partNumber: number, partToken: string): Promise<void> => {
        const part = parts[partNumber - 1]
        if (!part) return
        const plain = new Uint8Array(
          await file.slice(part.offset, part.offset + part.plaintextLength).arrayBuffer(),
        )
        const sealed = await sealPart(
          master,
          created.share_id,
          session.file_id,
          prefix,
          startingIndex(part),
          plain,
          partNumber === lastNumber,
        )
        const digest = await sha256Hex(sealed.ciphertext.slice().buffer)
        const resp = await putPart(
          csrf,
          session.session_id,
          partNumber,
          sealed.ciphertext.slice().buffer as ArrayBuffer,
          digest,
          partToken,
        )
        tokenPool.push(...(resp.next_tokens ?? []))
        progress.value.done++
      }
      while (firstError === null && (nextPart <= parts.length || tokenPool.length > 0)) {
        const inFlight: Array<Promise<void>> = []
        while (nextPart <= parts.length && tokenPool.length > 0 && inFlight.length < 2) {
          const n = nextPart++
          const tok = tokenPool.shift()!
          inFlight.push(send(n, tok).catch((e) => (firstError ??= e)))
        }
        if (inFlight.length === 0) break
        await Promise.race(inFlight)
        await Promise.allSettled(inFlight)
      }
      if (firstError !== null) throw firstError
      await completeSession(csrf, session.session_id, session.first_tokens[0] ?? '')
      const fp = await sha256Hex(await file.arrayBuffer())
      manifestFiles.push({
        id: session.file_id,
        name: file.name,
        mime: file.type || 'application/octet-stream',
        size: file.size,
        sha256: fp,
      })
    }

    const blobs = await sealManifest(master, created.share_id, {
      title: title.value.trim(),
      body: body.value,
      files: manifestFiles,
      ...(notifyEmail.value.trim() !== '' ? { notify_email: notifyEmail.value.trim() } : {}),
    })
    await finalizeShare(csrf, created.share_id, {
      title_ct: toB64(blobs.titleCt),
      manifest_ct: toB64(blobs.manifestCt),
      check_ct: toB64(blobs.checkCt),
    })

    saveMineRecord({
      shareID: created.share_id,
      managerToken: created.manager_token,
      title: title.value.trim(),
      createdAt: Date.now(),
      expiryMode: expiryMode.value,
      expiresAt: expiryMode.value === 'ttl' ? Date.now() + expiryDays.value * 86400_000 : 0,
    })

    router.push({ path: '/uploaded', query: { s: created.share_id } })
  } catch (e) {
    error.value = (e as Error).message
    // a token dies with the attempt that used it, even a failed one
    widget?.reset()
    turnstileToken.value = ''
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="stage" @keydown="onKey">
    <!-- one element, two states: the brand blue circle morphs into the card -->
    <div class="morph" :class="{ open }">
      <!-- the closed state: brand accent circle with the +, breathing glow.
           the click lives here on the button, a wrapper level handler would
           refire on clicks bubbling out of the open card and undo the close -->
      <button
        v-if="!open"
        type="button"
        class="fab-inner"
        aria-label="New share, click to upload"
        @click="toggle()"
      >
        <span class="halo halo-outer" aria-hidden="true"></span>
        <span class="halo halo-inner" aria-hidden="true"></span>
        <svg
          class="plus"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="2.5"
          stroke-linecap="round"
        >
          <path d="M12 5v14M5 12h14" />
        </svg>
      </button>

      <!-- the open state: the same element grown into the two column card -->
      <div v-if="open" class="form">
        <button type="button" class="close" aria-label="Close" @click="toggle()">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
            <path d="M6 6l12 12M18 6L6 18" />
          </svg>
        </button>

        <header class="form-head">
          <h2>Share something</h2>
          <p class="form-sub">Files are encrypted in your browser before they are sent.</p>
        </header>
        <p v-if="error" class="error" role="alert">{{ error }}</p>

        <div class="cols">
          <!-- right on desktop, first on mobile: the files -->
          <section class="col col-files" @click.stop>
            <div
              class="drop"
              :class="{ over: dragOver }"
              @dragover.prevent="dragOver = true"
              @dragleave="dragOver = false"
              @drop.prevent="onDrop"
            >
              <span class="drop-icon">
                <svg
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="1.6"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                >
                  <path d="M4 14.899A7 7 0 1 1 15.71 8h1.79a4.5 4.5 0 0 1 2.5 8.242" />
                  <path d="M12 12v9" />
                  <path d="m16 16-4-4-4 4" />
                </svg>
              </span>
              <p class="drop-title">Drop files here</p>
              <button type="button" class="browse" @click="fileInput?.click()">or browse</button>
              <input
                ref="fileInput"
                type="file"
                multiple
                hidden
                @change="pickFiles(($event.target as HTMLInputElement).files)"
              />
            </div>

            <div v-if="files.length" class="manifest">
              <div class="manifest-head">
                <span class="manifest-label">Attached files</span>
                <span v-if="progress.total > 0" class="manifest-parts" role="status"
                  >{{ progress.done }} / {{ progress.total }} parts sent</span
                >
              </div>
              <ul class="files">
                <li v-for="(f, i) in files" :key="i">
                  <span class="file-icon" aria-hidden="true">
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
                  <span class="file-meta">
                    <span class="name">{{ f.name }}</span>
                    <span class="size">{{ f.size.toLocaleString() }} bytes</span>
                  </span>
                  <button
                    type="button"
                    class="remove"
                    @click="removeFile(i)"
                    :aria-label="`Remove ${f.name}`"
                  >
                    <svg
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      stroke-width="2"
                      stroke-linecap="round"
                    >
                      <path d="M6 6l12 12M18 6L6 18" />
                    </svg>
                  </button>
                </li>
              </ul>
              <div v-if="progress.total > 0" class="track">
                <div class="fill" :style="{ width: `${progressPct}%` }"></div>
              </div>
            </div>

            <p v-if="tooBig" class="error">Over the size limit for one share.</p>
            <p v-if="tooMany" class="error">Too many files.</p>
          </section>

          <!-- left on desktop, second on mobile: the details -->
          <section class="col col-fields">
            <label class="field">
              <span class="field-label">Title <span class="req">required</span></span>
              <input ref="titleInput" v-model="title" maxlength="200" placeholder="What is this?" />
            </label>

            <label class="field">
              <span class="field-label">Message <span class="opt">optional, markdown</span></span>
              <textarea v-model="body" rows="4" placeholder="A note for the recipient"></textarea>
            </label>

            <label class="field">
              <span class="field-label">Notify me on download <span class="opt">optional</span></span>
              <span class="email-wrap">
                <svg
                  class="email-icon"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="1.8"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  aria-hidden="true"
                >
                  <circle cx="12" cy="12" r="4" />
                  <path d="M16 8v5a3 3 0 0 0 6 0v-1a10 10 0 1 0-4 8" />
                </svg>
                <input v-model="notifyEmail" type="email" placeholder="your@email.com" />
              </span>
            </label>

            <fieldset class="expiry">
              <legend class="field-label">After download</legend>
              <div class="expiry-grid">
                <label class="radio-card" :class="{ selected: expiryMode === 'burn_on_ack' }">
                  <input type="radio" value="burn_on_ack" v-model="expiryMode" />
                  <span class="radio-body">
                    <span class="radio-title">Wipe once downloaded</span>
                    <!-- the 7 day ceiling matches the server side burn limit,
                     if that constant ever changes this copy must follow -->
                    <span class="radio-sub">
                      Files delete themselves after the recipient gets them, or after 7 days if unopened.
                    </span>
                  </span>
                  <span v-if="expiryMode === 'burn_on_ack'" class="pill">Recommended</span>
                </label>
                <label class="radio-card" :class="{ selected: expiryMode === 'ttl' }">
                  <input type="radio" value="ttl" v-model="expiryMode" />
                  <span class="radio-body">
                    <span class="radio-title">
                      Keep
                      <select v-model.number="expiryDays" :disabled="expiryMode !== 'ttl'" @click.stop>
                        <option v-for="d in info?.limits.expiry_days ?? [1, 3, 7]" :key="d" :value="d">
                          {{ d }} day{{ d > 1 ? 's' : '' }}
                        </option>
                      </select>
                    </span>
                    <span class="radio-sub">
                      Files will be available for unlimited download for {{ expiryDays }}
                      {{ expiryDays > 1 ? 'days' : 'day' }}.
                    </span>
                  </span>
                </label>
              </div>
            </fieldset>
          </section>
        </div>

        <div v-show="turnstileEnforced" ref="turnstileBox" class="ts-box"></div>

        <div class="tray">
          <div class="tray-actions">
            <button type="button" class="btn-ghost" :disabled="busy" @click="toggle()">Cancel</button>
            <button type="button" class="btn-primary" :disabled="!canSubmit" @click="submit">
              {{ busy ? 'Sending…' : 'Create share' }}
              <svg
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
                aria-hidden="true"
              >
                <path d="M5 12h14M12 5l7 7-7 7" />
              </svg>
            </button>
          </div>
        </div>
      </div>
    </div>
    <p v-if="!open" class="hint">click to upload</p>
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

/* the morph: one element, blue circle at rest, white card when open */
.morph {
  view-transition-name: page-card;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 7.5rem;
  height: 7.5rem;
  border-radius: 9999px;
  background: var(--accent);
  overflow: hidden;
  cursor: pointer;
  transition:
    width 420ms cubic-bezier(0.34, 1.3, 0.4, 1),
    height 420ms cubic-bezier(0.34, 1.3, 0.4, 1),
    min-height 420ms cubic-bezier(0.34, 1.3, 0.4, 1),
    border-radius 420ms cubic-bezier(0.34, 1.3, 0.4, 1),
    padding 420ms cubic-bezier(0.34, 1.3, 0.4, 1),
    background-color 300ms ease,
    box-shadow 300ms ease,
    border-color 300ms ease;
  border: 1px solid transparent;
  box-shadow: 0 10px 30px rgba(92, 153, 238, 0.35);
}

.morph.open {
  width: min(64rem, calc(100vw - 2rem));
  height: auto;
  border-radius: 16px;
  background: var(--card);
  border-color: var(--outline-soft);
  padding: 2rem;
  cursor: default;
  overflow: visible;
  box-shadow: 0 20px 48px rgba(52, 71, 97, 0.12);
}

.morph:not(.open):hover {
  transform: translateY(-3px);
  box-shadow: 0 15px 40px rgba(92, 153, 238, 0.45);
}

/* the + inside the circle, with its breathing halo */
.fab-inner {
  position: relative;
  width: 100%;
  height: 100%;
  border: none;
  background: none;
  color: var(--on-accent);
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  padding: 0;
}

.fab-inner .plus {
  width: 2.75rem;
  height: 2.75rem;
  transition: transform 0.2s ease;
}

.morph:not(.open):hover .plus {
  transform: scale(1.15);
}

.halo {
  position: absolute;
  inset: 0;
  border-radius: 50%;
  pointer-events: none;
}

.halo-outer {
  box-shadow: 0 0 0 14px rgba(92, 153, 238, 0.12);
  animation: breathe 4s ease-in-out infinite;
}

.halo-inner {
  box-shadow: 0 0 0 6px rgba(92, 153, 238, 0.18);
}

@keyframes breathe {
  0%,
  100% {
    box-shadow: 0 0 0 10px rgba(92, 153, 238, 0.1);
  }
  50% {
    box-shadow: 0 0 0 18px rgba(92, 153, 238, 0.06);
  }
}

.hint {
  margin: 0;
  font-size: 12px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--on-surface-variant);
  opacity: 0.55;
}

/* the form inside the morphed card */
.form {
  width: 100%;
  display: flex;
  flex-direction: column;
  gap: 1.4rem;
  animation: fade-in 220ms ease 180ms both;
}

@keyframes fade-in {
  from {
    opacity: 0;
    transform: translateY(0.5rem);
  }
  to {
    opacity: 1;
    transform: none;
  }
}

.close {
  position: absolute;
  top: 1.1rem;
  right: 1.1rem;
  width: 2rem;
  height: 2rem;
  border: none;
  background: var(--surface-high);
  border-radius: 50%;
  color: var(--on-surface-variant);
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition:
    background 0.2s,
    color 0.2s;
  z-index: 1;
}

.close:hover {
  background: var(--surface-highest);
  color: var(--on-surface);
}

.close svg {
  width: 1rem;
  height: 1rem;
}

.form-head h2 {
  font-size: 24px;
  margin: 0;
}

.form-sub {
  margin: 0.2rem 0 0;
  font-size: 13px;
  color: var(--on-surface-variant);
}

/* the two columns: files right on desktop, files first on mobile */
.cols {
  display: grid;
  grid-template-columns: 1fr;
  grid-template-areas:
    'files'
    'fields';
  gap: 1.4rem;
  align-items: start;
}

.col-files {
  grid-area: files;
}

.col-fields {
  grid-area: fields;
  display: flex;
  flex-direction: column;
  gap: 1.1rem;
}

@media (min-width: 1024px) {
  .cols {
    grid-template-columns: minmax(0, 7fr) minmax(0, 5fr);
    grid-template-areas: 'fields files';
    gap: 2rem;
  }
}

/* drop zone */
.drop {
  border: 2px dashed var(--outline-variant);
  border-radius: 12px;
  padding: 1.8rem 1rem;
  text-align: center;
  transition:
    border-color 0.2s,
    background 0.2s;
}

.drop.over {
  border-color: var(--accent);
  background: rgba(92, 153, 238, 0.08);
}

.drop-icon {
  display: inline-flex;
  width: 3rem;
  height: 3rem;
  border-radius: 50%;
  background: rgba(92, 153, 238, 0.1);
  color: var(--accent);
  align-items: center;
  justify-content: center;
  margin-bottom: 0.5rem;
  transition: transform 0.2s;
}

.drop:hover .drop-icon {
  transform: scale(1.05);
}

.drop-icon svg {
  width: 1.6rem;
  height: 1.6rem;
}

.drop-title {
  margin: 0 0 0.6rem;
  font-weight: 500;
  color: var(--on-surface);
}

.browse {
  background: transparent;
  border: 1px solid var(--outline-variant);
  border-radius: 8px;
  color: var(--on-surface-variant);
  font-size: 12px;
  font-weight: 500;
  letter-spacing: 0.6px;
  padding: 7px 16px;
  cursor: pointer;
  transition:
    border-color 0.2s,
    color 0.2s;
}

.browse:hover {
  border-color: var(--accent);
  color: var(--accent-deep);
}

/* attached files manifest */
.manifest {
  margin-top: 0.9rem;
  border: 1px solid var(--outline-soft);
  border-radius: 12px;
  background: rgba(238, 244, 255, 0.4);
  padding: 0.9rem;
  display: flex;
  flex-direction: column;
  gap: 0.7rem;
}

.manifest-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.manifest-label {
  font-size: 12px;
  font-weight: 500;
  letter-spacing: 0.5px;
  text-transform: uppercase;
  color: var(--on-surface-variant);
}

.manifest-parts {
  font-size: 12px;
  font-weight: 500;
  color: var(--accent-deep);
}

.files {
  list-style: none;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.files li {
  display: flex;
  gap: 0.75rem;
  align-items: center;
  padding: 0.6rem 0.7rem;
  border-radius: 10px;
  background: var(--card);
  border: 1px solid var(--outline-soft);
}

.file-icon {
  display: flex;
  width: 2.1rem;
  height: 2.1rem;
  border-radius: 8px;
  background: rgba(92, 153, 238, 0.1);
  color: var(--accent-deep);
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.file-icon svg {
  width: 1rem;
  height: 1rem;
}

.file-meta {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
}

.files .name {
  font-weight: 500;
  font-size: 13px;
  overflow-wrap: anywhere;
}

.files .size {
  font-size: 11px;
  color: var(--on-surface-variant);
}

.remove {
  border: none;
  background: transparent;
  border-radius: 50%;
  width: 1.75rem;
  height: 1.75rem;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--on-surface-variant);
  cursor: pointer;
  transition:
    color 0.2s,
    background 0.2s;
  flex-shrink: 0;
}

.remove:hover {
  color: var(--error);
  background: var(--error-soft);
}

.remove svg {
  width: 0.85rem;
  height: 0.85rem;
}

/* hairline progress */
.track {
  width: 100%;
  height: 5px;
  border-radius: 9999px;
  background: var(--surface-highest);
  overflow: hidden;
}

.fill {
  height: 100%;
  border-radius: 9999px;
  background: var(--accent);
  transition: width 0.3s ease;
}

/* fields */
.field {
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}

.field-label {
  font-size: 14px;
  font-weight: 500;
  color: var(--on-surface);
}

.req {
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--accent-deep);
  background: rgba(92, 153, 238, 0.1);
  border-radius: 4px;
  padding: 1px 6px;
  vertical-align: 1px;
}

.opt {
  font-size: 12px;
  font-weight: 400;
  color: var(--on-surface-variant);
}

.field input,
.field textarea {
  font: inherit;
  color: var(--on-surface);
  padding: 10px 14px;
  border: 1px solid var(--outline-variant);
  border-radius: 8px;
  background: var(--card);
  transition:
    border-color 0.2s,
    box-shadow 0.2s;
  width: 100%;
}

.field input:focus,
.field textarea:focus {
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 2px rgba(92, 153, 238, 0.2);
}

.field input::placeholder,
.field textarea::placeholder {
  color: var(--on-surface-variant);
  opacity: 0.6;
}

.email-wrap {
  position: relative;
  display: block;
}

.email-icon {
  position: absolute;
  left: 12px;
  top: 50%;
  transform: translateY(-50%);
  width: 1rem;
  height: 1rem;
  color: var(--on-surface-variant);
  pointer-events: none;
}

.email-wrap input {
  padding-left: 2.4rem;
}

/* expiry radio cards, two up on wider screens */
.expiry {
  border: none;
  padding: 0;
  margin: 0;
}

.expiry legend {
  padding: 0;
  margin-bottom: 0.5rem;
}

.expiry-grid {
  display: grid;
  grid-template-columns: 1fr;
  gap: 0.6rem;
}

@media (min-width: 560px) {
  .expiry-grid {
    grid-template-columns: 1fr 1fr;
  }
}

.radio-card {
  position: relative;
  display: flex;
  gap: 0.7rem;
  align-items: flex-start;
  padding: 0.75rem;
  border-radius: 12px;
  border: 1px solid var(--outline-soft);
  background: var(--card);
  cursor: pointer;
  transition:
    background 0.2s,
    border-color 0.2s,
    box-shadow 0.2s;
}

.radio-card:hover {
  background: var(--surface-low);
}

.radio-card.selected {
  background: rgba(92, 153, 238, 0.05);
  border-color: var(--accent);
  box-shadow: 0 5px 15px rgba(92, 153, 238, 0.1);
}

.radio-card input {
  margin-top: 0.25rem;
  accent-color: var(--accent);
}

.radio-body {
  display: flex;
  flex-direction: column;
  gap: 0.15rem;
}

.radio-title {
  font-weight: 500;
  font-size: 14px;
  color: var(--on-surface);
}

.pill {
  position: absolute;
  top: -13px;
  right: 10px;
  font-size: 9px;
  font-weight: 600;
  letter-spacing: 0.5px;
  text-transform: uppercase;
  color: var(--on-accent);
  background: var(--accent);
  border-radius: 9999px;
  padding: 2px 8px;
}

.radio-sub {
  font-size: 12px;
  color: var(--on-surface-variant);
}

.radio-sub select {
  font: inherit;
  font-size: 12px;
  border: 1px solid var(--outline-variant);
  border-radius: 6px;
  padding: 2px 6px;
  background: var(--card);
  color: var(--on-surface);
  margin-left: 0.25rem;
}

.error {
  color: var(--error);
  margin: 0;
  font-size: 14px;
}

.ts-box {
  min-height: 65px;
  display: flex;
  justify-content: center;
}

/* action tray */
.tray {
  border-top: 1px solid var(--outline-soft);
  padding-top: 1.1rem;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  flex-wrap: wrap;
}

.tray-actions {
  display: flex;
  gap: 0.75rem;
  margin-left: auto;
}

.tray-actions .btn-primary {
  padding: 12px 28px;
}

.tray-actions .btn-primary svg {
  width: 1rem;
  height: 1rem;
}

@media (max-width: 640px) {
  .stage {
    min-height: calc(100vh - 13rem);
  }

  .morph.open {
    padding: 1.25rem;
  }

  .tray {
    flex-direction: column;
    align-items: stretch;
  }

  .tray-actions {
    margin-left: 0;
    flex-direction: column-reverse;
  }

  .tray-actions .btn-primary,
  .tray-actions .btn-ghost {
    width: 100%;
  }
}

@media (prefers-reduced-motion: reduce) {
  .morph,
  .morph .plus,
  .form,
  .halo-outer {
    transition: none;
    animation: none;
  }
}
</style>
