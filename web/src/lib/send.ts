// The send pipeline outlives the composer view. the form fills a draft,
// the sending view watches this store run it, so navigation between the
// two never interrupts an upload in flight.
import { reactive } from 'vue'
import { csrfCookie, createShare, putPart, completeSession, finalizeShare, type BootstrapInfo } from './api'
import { planParts, sealPart, startingIndex, freshNoncePrefix, ciphertextSize } from './pipeline'
import { generateMasterKey, encodeFragmentKey } from '../crypto/frame'
import { sealManifest, toB64, type ManifestFile } from './manifest'
import { saveMineRecord } from './mine'

export interface SendDraft {
  title: string
  body: string
  notifyEmail: string
  expiryMode: 'burn_on_ack' | 'ttl'
  expiryDays: number
}

export type SendPhase = 'idle' | 'needs-token' | 'sending' | 'done' | 'error'

export interface SendFileProgress {
  name: string
  size: number
  sentParts: number
  totalParts: number
  sentBytes: number
  totalBytes: number
}

// module scope on purpose: a component instance dies with its route, the
// upload must not
const state = reactive({
  phase: 'idle' as SendPhase,
  draft: null as SendDraft | null,
  files: [] as File[],
  perFile: [] as SendFileProgress[],
  error: '',
  shareId: '',
  enforced: false,
})

let ac: AbortController | null = null // one controller per run, replaced on start
let running = false

export function sendStarted(): boolean {
  return running
}

export function sendState() {
  return state
}

// the composer hands over its draft and files, the sending view takes it
// from here. needsToken parks the run until the view supplies a human
// check token
export function stageSend(draft: SendDraft, files: File[], info: BootstrapInfo): void {
  state.enforced = info.turnstile.enforced
  state.draft = draft
  state.files = files
  state.perFile = files.map((f) => {
    const parts = planParts(f.size, info.limits.chunk_max_bytes)
    return {
      name: f.name,
      size: f.size,
      sentParts: 0,
      totalParts: parts.length,
      sentBytes: 0,
      totalBytes: parts.reduce((acc, p) => acc + ciphertextSize(p.plaintextLength), 0),
    }
  })
  state.error = ''
  state.shareId = ''
  running = false
  state.phase = state.enforced ? 'needs-token' : 'sending'
}

async function sha256Hex(buf: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', buf)
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

export function cancelSend(): void {
  ac?.abort()
  resetSend()
}

function resetSend(): void {
  running = false
  state.phase = 'idle'
  state.draft = null
  state.files = []
  state.perFile = []
  state.error = ''
  state.shareId = ''
}

// the whole send: create, parts, complete, seal, finalize. the engine is
// the one the composer ran inline before, only the progress bookkeeping
// grew per file counters
export async function startSend(info: BootstrapInfo, turnstileToken: string): Promise<void> {
  const draft = state.draft
  if (!draft || running) {
    if (!draft) {
      state.phase = 'error'
      state.error = 'nothing staged'
    }
    return
  }

  ac = new AbortController()
  running = true
  const { signal } = ac
  state.phase = 'sending'
  state.error = ''
  try {
    const master = generateMasterKey()
    const fragment = encodeFragmentKey(master)
    const chunk = info.limits.chunk_max_bytes
    const csrf = csrfCookie()

    const staged = state.files.map((f) => ({ file: f, parts: planParts(f.size, chunk) }))
    state.perFile = staged.map((s) => ({
      name: s.file.name,
      size: s.file.size,
      sentParts: 0,
      totalParts: s.parts.length,
      sentBytes: 0,
      totalBytes: s.parts.reduce((acc, p) => acc + ciphertextSize(p.plaintextLength), 0),
    }))

    const created = await createShare(
      csrf,
      {
        files: staged.map((s) => ({
          size: s.parts.reduce((acc, p) => acc + ciphertextSize(p.plaintextLength), 0),
          frame_count: Math.ceil(s.file.size / info.limits.frame_size),
          frame_size: info.limits.frame_size,
          part_size: chunk,
          expected_parts: s.parts.length,
        })),
        expiry_mode: draft.expiryMode,
        expiry_days: draft.expiryDays,
        notify_wanted: draft.notifyEmail.trim() !== '',
      },
      turnstileToken,
      signal,
    )
    state.shareId = created.share_id

    // per share slot: a single slot would let a failed later upload
    // destroy the only key copy of an earlier live share
    const handoffKey = `dreamshare.handoff.v1.${created.share_id}`
    try {
      sessionStorage.setItem(
        handoffKey,
        JSON.stringify({ s: created.share_id, k: fragment, m: created.manager_token }),
      )
    } catch (storageErr) {
      throw new Error(`cannot store the link: ${(storageErr as Error).message}. Nothing was uploaded.`, {
        cause: storageErr,
      })
    }

    const manifestFiles: ManifestFile[] = []
    for (let i = 0; i < staged.length; i++) {
      const entry = staged[i]
      const session = created.upload_sessions[i]
      if (!entry || !session) throw new Error('session_missing')
      const { file, parts } = entry
      const prefix = await freshNoncePrefix()
      const lastNumber = parts[parts.length - 1]?.number ?? 1

      // tokens are positional, each one is the hmac
      // of its own part number, so they are tracked per part: a flat
      // queue desynced on the look ahead refill and handed a used token
      // to a later part, which the server rightly refused
      const tokenMap = new Map<number, string>()
      session.first_tokens.forEach((t, j) => tokenMap.set(j + 1, t))
      let nextPart = 1
      let firstError: unknown = null
      // byte counters sit beside the part counters: a part in flight for
      // tens of seconds moves bytes the whole time, and the bars follow
      let doneBytes = 0
      const inflight = new Map<number, number>()
      const syncBytes = () => {
        let moving = 0
        inflight.forEach((v) => (moving += v))
        const row = state.perFile[i]
        if (row) row.sentBytes = doneBytes + moving
      }
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
          signal,
          (loaded) => {
            inflight.set(partNumber, loaded)
            syncBytes()
          },
        )
        ;(resp.next_tokens ?? []).forEach((t, j) => tokenMap.set(partNumber + 1 + j, t))
        const row = state.perFile[i]
        if (row) row.sentParts++
        doneBytes += sealed.ciphertext.byteLength
        inflight.delete(partNumber)
        syncBytes()
      }
      // one part in flight. two split the uplink and crawl together, one
      // moves steadily and the byte bars follow it. the three token look
      // ahead on the server side still covers this with room to spare
      const MAX_IN_FLIGHT = 1
      while (firstError === null && nextPart <= parts.length && !signal.aborted) {
        const inFlight: Array<Promise<void>> = []
        while (nextPart <= parts.length && tokenMap.has(nextPart) && inFlight.length < MAX_IN_FLIGHT) {
          const n = nextPart++
          inFlight.push(send(n, tokenMap.get(n)!).catch((e) => (firstError ??= e)))
        }
        if (inFlight.length === 0) break
        await Promise.race(inFlight)
        await Promise.allSettled(inFlight)
      }
      if (signal.aborted) return
      if (firstError !== null) throw firstError
      await completeSession(csrf, session.session_id, session.first_tokens[0] ?? '', signal)
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
      title: draft.title,
      body: draft.body,
      files: manifestFiles,
      ...(draft.notifyEmail.trim() !== '' ? { notify_email: draft.notifyEmail.trim() } : {}),
    })
    await finalizeShare(
      csrf,
      created.share_id,
      {
        title_ct: toB64(blobs.titleCt),
        manifest_ct: toB64(blobs.manifestCt),
        check_ct: toB64(blobs.checkCt),
      },
      signal,
    )

    saveMineRecord({
      shareID: created.share_id,
      managerToken: created.manager_token,
      title: draft.title,
      createdAt: Date.now(),
      expiryMode: draft.expiryMode,
      expiresAt: draft.expiryMode === 'ttl' ? Date.now() + draft.expiryDays * 86400_000 : 0,
    })

    state.files = []
    state.perFile = []
    state.draft = null
    running = false
    state.phase = 'done'
  } catch (e) {
    if (signal.aborted) return
    running = false
    state.phase = 'error'
    state.error = (e as Error).message
  }
}

// a retry is a fresh share: new key, new create, the abandoned half
// upload is swept by the server inside a day
export function retrySend(info: BootstrapInfo): void {
  if (!state.draft) return
  state.error = ''
  state.phase = state.enforced ? 'needs-token' : 'sending'
  if (!state.enforced) void startSend(info, '')
}
