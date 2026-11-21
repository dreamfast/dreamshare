// The send pipeline outlives the composer view. the form fills a draft,
// the sending view watches this store run it, so navigation between the
// two never interrupts an upload in flight.
import { reactive } from 'vue'
import {
  csrfCookie,
  createShare,
  putPart,
  completeSession,
  finalizeShare,
  type BootstrapInfo,
  type CreatedShare,
} from './api'
import { planParts, sealPart, startingIndex, freshNoncePrefix, ciphertextSize } from './pipeline'
import { deriveWorkingKey, generateMasterKey, encodeFragmentKey } from '../crypto/frame'
import { sealManifest, toB64, fromB64, type ManifestFile } from './manifest'
import { saveMineRecord } from './mine'

export interface SendDraft {
  title: string
  body: string
  notifyEmail: string
  passphrase: string
  expiryMode: 'burn_on_ack' | 'ttl'
  expiryDays: number
}

export type SendPhase = 'idle' | 'resumable' | 'needs-token' | 'sending' | 'done' | 'error'

export interface SendFileProgress {
  name: string
  size: number
  sentParts: number
  totalParts: number
  sentBytes: number
  totalBytes: number
}

// one file's place in the run: enough to continue after a failure or a
// reload, the file object itself can only come from a fresh pick
export interface ResumeSession {
  sessionId: string
  fileId: string
  uploadId: string
  fileName: string
  fileSize: number
  fileType: string
  parts: Array<{ number: number; offset: number; plaintextLength: number }>
  tokenMap: Record<string, string>
  nextPart: number
  sentParts: number
  done: boolean
  manifest: { id: string; name: string; mime: string; size: number; sha256: string } | null
}

export interface SendProgress {
  shareId: string
  managerToken: string
  workingKeyB64: string
  // the draft without the passphrase, the working key is already derived
  draft: Omit<SendDraft, 'passphrase'>
  sessions: ResumeSession[]
  finalized: boolean
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
  progress: null as SendProgress | null,
})

const RESUME_KEY = 'dreamshare.resume.v1'

function persistProgress(): void {
  if (!state.progress) return
  try {
    sessionStorage.setItem(RESUME_KEY, JSON.stringify(state.progress))
  } catch {
    // a full or blocked storage must never kill the upload itself
  }
}

function clearProgress(): void {
  state.progress = null
  try {
    sessionStorage.removeItem(RESUME_KEY)
  } catch {
    // same
  }
}

// a saved run exists and has somewhere to go
export function savedProgress(): SendProgress | null {
  try {
    const raw = sessionStorage.getItem(RESUME_KEY)
    if (!raw) return null
    const p = JSON.parse(raw) as SendProgress
    if (!p.shareId || p.finalized || p.sessions.length === 0) return null
    return p
  } catch {
    return null
  }
}

// adopt a saved run after a reload: the visitor re picks the files, they
// match by name and size, and the run continues where it stopped
export function adoptProgress(p: SendProgress, files: File[]): string {
  const byKey = new Map(files.map((f) => [`${f.name}|${f.size}`, f]))
  // files go back in SESSION order, a different pick order must never
  // pair a file with another session's part plan. done sessions get a
  // placeholder, their bytes are already stored and their manifest entry
  // already carries the hash.
  let orderErr = ''
  const ordered: File[] = p.sessions.map((sess) => {
    if (sess.done) return new File([], sess.fileName, { type: sess.fileType })
    const match = byKey.get(`${sess.fileName}|${sess.fileSize}`)
    if (!match) {
      orderErr = `pick ${sess.fileName} again, same size, to continue`
      return new File([], sess.fileName)
    }
    byKey.delete(`${sess.fileName}|${sess.fileSize}`)
    return match
  })
  if (orderErr !== '') return orderErr
  state.progress = p
  state.shareId = p.shareId
  state.files = ordered
  // the manifest seal needs the draft, the passphrase is spent into the
  // working key and never needed again
  state.draft = { ...p.draft, passphrase: '' }
  state.perFile = p.sessions.map((sess) => ({
    name: sess.fileName,
    size: sess.fileSize,
    sentParts: sess.sentParts,
    totalParts: sess.parts.length,
    sentBytes: 0,
    totalBytes: sess.parts.reduce((acc, pt) => acc + ciphertextSize(pt.plaintextLength), 0),
  }))
  state.error = ''
  state.phase = state.enforced ? 'needs-token' : 'sending'
  return ''
}

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
  clearProgress()
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
  // cancel means abandon, the saved run must not hijack the next one
  clearProgress()
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
    const chunk = info.limits.chunk_max_bytes
    const csrf = csrfCookie()
    let master: Uint8Array
    let fragment = ''
    let staged: Array<{ file: File; parts: ReturnType<typeof planParts> }>
    let created: CreatedShare
    const manifestFiles: ManifestFile[] = []

    if (state.progress) {
      // a continuation: the share exists, the key exists, pick up the
      // parts where they stopped
      master = fromB64(state.progress.workingKeyB64)
      // the persisted plan is the truth, a placeholder size must never
      // re-plan a done session into different offsets
      staged = state.progress.sessions.map((sess) => ({
        file:
          state.files.find((f) => f.name === sess.fileName && f.size === sess.fileSize) ??
          new File([], sess.fileName),
        parts: sess.parts.map((pt) => ({
          number: pt.number,
          offset: pt.offset,
          plaintextLength: pt.plaintextLength,
        })),
      }))
      created = {
        share_id: state.progress.shareId,
        manager_token: state.progress.managerToken,
        upload_sessions: state.progress.sessions.map((sess) => ({
          session_id: sess.sessionId,
          file_id: sess.fileId,
          expected_parts: sess.parts.length,
          part_size: chunk,
          multipart: sess.parts.length > 1,
          first_tokens: (Object.entries(sess.tokenMap) as Array<[string, string]>)
            .sort((a, b) => Number(a[0]) - Number(b[0]))
            .slice(0, 3)
            .map(([, t]) => t),
        })),
      }
      for (const sess of state.progress.sessions) {
        if (sess.manifest) manifestFiles.push(sess.manifest)
      }
    } else {
      const rawMaster = generateMasterKey()
      fragment = encodeFragmentKey(rawMaster)
      // a passphrase mixes into every seal through a working key, the
      // fragment alone can no longer open the share
      master = rawMaster
      let kdf: { salt: string; iters: number } | undefined
      if (draft.passphrase !== '') {
        const salt = globalThis.crypto.getRandomValues(new Uint8Array(16))
        // owasp aligned, the server accepts up to five million
        const iters = 600_000
        master = await deriveWorkingKey(rawMaster, draft.passphrase, salt, iters)
        kdf = { salt: toB64(salt), iters }
      }
      staged = state.files.map((f) => ({ file: f, parts: planParts(f.size, chunk) }))
      state.perFile = staged.map((s2) => ({
        name: s2.file.name,
        size: s2.file.size,
        sentParts: 0,
        totalParts: s2.parts.length,
        sentBytes: 0,
        totalBytes: s2.parts.reduce((acc, p) => acc + ciphertextSize(p.plaintextLength), 0),
      }))
      created = await createShare(
        csrf,
        {
          files: staged.map((s2) => ({
            size: s2.parts.reduce((acc, p) => acc + ciphertextSize(p.plaintextLength), 0),
            frame_count: Math.ceil(s2.file.size / info.limits.frame_size),
            frame_size: info.limits.frame_size,
            part_size: chunk,
            expected_parts: s2.parts.length,
          })),
          expiry_mode: draft.expiryMode,
          expiry_days: draft.expiryDays,
          ...(draft.notifyEmail.trim() !== '' ? { notify_email: draft.notifyEmail.trim() } : {}),
          ...(kdf ? { passphrase_kdf: kdf } : {}),
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

      // the run is resumable from here: every part that lands updates this
      state.progress = {
        shareId: created.share_id,
        managerToken: created.manager_token,
        workingKeyB64: toB64(master),
        draft: {
          title: draft.title,
          body: draft.body,
          notifyEmail: draft.notifyEmail,
          expiryMode: draft.expiryMode,
          expiryDays: draft.expiryDays,
        },
        finalized: false,
        sessions: staged.map((st, i) => ({
          sessionId: created.upload_sessions[i]?.session_id ?? '',
          fileId: created.upload_sessions[i]?.file_id ?? '',
          uploadId: '',
          fileName: st.file.name,
          fileSize: st.file.size,
          fileType: st.file.type || 'application/octet-stream',
          parts: st.parts.map((pt) => ({
            number: pt.number,
            offset: Number(pt.offset),
            plaintextLength: pt.plaintextLength,
          })),
          tokenMap: Object.fromEntries(
            (created.upload_sessions[i]?.first_tokens ?? []).map((t: string, j: number) => [
              String(j + 1),
              t,
            ]),
          ),
          nextPart: 1,
          sentParts: 0,
          done: false,
          manifest: null,
        })),
      }
      persistProgress()
    }

    for (let i = 0; i < staged.length; i++) {
      const entry = staged[i]!
      const file = entry.file
      const sess = state.progress!.sessions[i]
      if (!entry || !sess) throw new Error('session_missing')
      if (sess.done) continue
      const parts = entry.parts
      const prefix = await freshNoncePrefix()
      const lastNumber = parts[parts.length - 1]?.number ?? 1

      // tokens are positional, each one is the hmac of its own part
      // number. the map survives the reload in the progress blob, a flat
      // queue desynced on the look ahead refill and handed a used token
      // to a later part, which the server rightly refused
      const tokenMap = new Map<number, string>(Object.entries(sess.tokenMap).map(([n, t]) => [Number(n), t]))
      let nextPart = sess.nextPart
      let firstError: unknown = null
      // byte counters sit beside the part counters: a part in flight for
      // tens of seconds moves bytes the whole time, and the bars follow
      let doneBytes = 0
      for (let pn = 1; pn < nextPart; pn++) {
        doneBytes += ciphertextSize(parts[pn - 1]?.plaintextLength ?? 0)
      }
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
          state.shareId,
          sess.fileId,
          prefix,
          startingIndex(part),
          plain,
          partNumber === lastNumber,
        )
        const digest = await sha256Hex(sealed.ciphertext.slice().buffer)
        const resp = await putPart(
          csrf,
          sess.sessionId,
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
        sess.tokenMap = Object.fromEntries(tokenMap)
        sess.nextPart = partNumber + 1
        sess.sentParts++
        const row = state.perFile[i]
        if (row) row.sentParts++
        doneBytes += sealed.ciphertext.byteLength
        inflight.delete(partNumber)
        syncBytes()
        persistProgress()
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
      await completeSession(csrf, sess.sessionId, tokenMap.get(1) ?? '', signal)
      const fp = await sha256Hex(await file.arrayBuffer())
      sess.done = true
      sess.manifest = {
        id: sess.fileId,
        name: file.name,
        mime: file.type || 'application/octet-stream',
        size: file.size,
        sha256: fp,
      }
      manifestFiles.push(sess.manifest)
      persistProgress()
    }

    const blobs = await sealManifest(master, created.share_id, {
      title: draft.title,
      body: draft.body,
      files: manifestFiles,
    })
    // the hash of the check verifier binds the ack to key possession
    const checkSHA = await sha256Hex(blobs.checkVerifier.slice().buffer as ArrayBuffer)
    await finalizeShare(
      csrf,
      created.share_id,
      {
        title_ct: toB64(blobs.titleCt),
        manifest_ct: toB64(blobs.manifestCt),
        check_ct: toB64(blobs.checkCt),
        check_sha256: checkSHA,
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

    clearProgress()
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
