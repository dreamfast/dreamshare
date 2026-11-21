// The browser side of the ds1 frame format. This file is the twin of
// internal/crypto/frame.go, and the interop fixtures prove the two agree.
// Constants must not drift from the Go side.

export const FORMAT_NAME = 'ds1'
export const FORMAT_VERSION = 0x01
export const FRAME_PLAINTEXT_MAX = 1 << 20
export const HEADER_SIZE = 13
export const TAG_SIZE = 16
export const FRAME_OVERHEAD = HEADER_SIZE + TAG_SIZE
export const NONCE_PREFIX_SIZE = 4
export const KEY_SIZE = 32
export const FRAGMENT_LENGTH = 43

export type Purpose = 'file' | 'manifest' | 'check' | 'title'

export function subkeyInfo(purpose: Purpose, id: string): string {
  return id ? `dreamshare:${purpose}:${id}` : `dreamshare:${purpose}`
}

/** HKDF-SHA256, empty salt, 256 bits, exactly like the Go side. */
export async function deriveSubkey(master: Uint8Array, info: string): Promise<CryptoKey> {
  if (master.length !== KEY_SIZE) {
    throw new Error(`master key must be ${KEY_SIZE} bytes, got ${master.length}`)
  }
  const base = await globalThis.crypto.subtle.importKey('raw', buf(master), 'HKDF', false, ['deriveBits'])
  const bits = await globalThis.crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: buf(utf8(info)) },
    base,
    256,
  )
  return globalThis.crypto.subtle.importKey('raw', bits, 'AES-GCM', false, ['encrypt', 'decrypt'])
}

/**
 * The working key for passphrase protected shares. The passphrase is
 * stretched with PBKDF2, then mixed into the fragment key through HKDF:
 * working = HKDF(ikm = master, salt = PBKDF2(passphrase), info = ds1).
 * Without a passphrase the caller uses the master key untouched, so the
 * two modes share every seal and open path below this line. The server
 * holds only the public parameters, salt and iteration count.
 */
export async function deriveWorkingKey(
  master: Uint8Array,
  passphrase: string,
  salt: Uint8Array,
  iters: number,
): Promise<Uint8Array> {
  if (master.length !== KEY_SIZE) {
    throw new Error(`master key must be ${KEY_SIZE} bytes, got ${master.length}`)
  }
  const passBase = await globalThis.crypto.subtle.importKey('raw', buf(utf8(passphrase)), 'PBKDF2', false, [
    'deriveBits',
  ])
  const passBits = await globalThis.crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: buf(salt), iterations: iters },
    passBase,
    256,
  )
  const hkdfBase = await globalThis.crypto.subtle.importKey('raw', buf(master), 'HKDF', false, ['deriveBits'])
  const bits = await globalThis.crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: passBits, info: buf(utf8('dreamshare:passphrase')) },
    hkdfBase,
    256,
  )
  return new Uint8Array(bits)
}

/** Canonical AAD: ds1, share id, purpose, uint64 index, last flag, NUL separated. */
export function aad(shareID: string, purpose: Purpose, index: bigint, last: boolean): Uint8Array {
  const head = new TextEncoder().encode(`${FORMAT_NAME}\0${shareID}\0${purpose}\0`)
  const out = new Uint8Array(head.length + 9)
  out.set(head, 0)
  const view = new DataView(out.buffer)
  view.setBigUint64(head.length, index, false)
  out[head.length + 8] = last ? 1 : 0
  return out
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s)
}

/** TS 5.9 types Uint8Array as ArrayBufferLike while WebCrypto wants a
 * concrete BufferSource, so hand it one. One copy, key sized, irrelevant. */
function buf(u: Uint8Array): ArrayBuffer {
  return u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer
}

export function newNoncePrefix(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(NONCE_PREFIX_SIZE))
}

/** Seals one frame. The frame counter is per object, not per chunk, and the
 * last flag must be passed in so a short chunk seals correctly. */
export async function sealFrame(
  key: CryptoKey,
  noncePrefix: Uint8Array,
  index: bigint,
  plaintext: Uint8Array,
  shareID: string,
  purpose: Purpose,
  last: boolean,
): Promise<Uint8Array> {
  if (plaintext.length === 0) {
    throw new Error('refusing to seal an empty frame, the format has no zero length frame')
  }
  if (plaintext.length > FRAME_PLAINTEXT_MAX) {
    throw new Error(`plaintext ${plaintext.length} bytes exceeds the frame maximum`)
  }
  const nonce = buildNonce(noncePrefix, index)
  const ct = new Uint8Array(
    await globalThis.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: buf(nonce),
        additionalData: buf(aad(shareID, purpose, index, last)),
        tagLength: 128,
      },
      key,
      buf(plaintext),
    ),
  )
  const frame = new Uint8Array(HEADER_SIZE + ct.length)
  frame[0] = FORMAT_VERSION
  frame.set(nonce, 1)
  frame.set(ct, HEADER_SIZE)
  return frame
}

export function buildNonce(prefix: Uint8Array, index: bigint): Uint8Array {
  if (prefix.length !== NONCE_PREFIX_SIZE) {
    throw new Error(`nonce prefix must be ${NONCE_PREFIX_SIZE} bytes`)
  }
  const nonce = new Uint8Array(12)
  nonce.set(prefix, 0)
  new DataView(nonce.buffer).setBigUint64(NONCE_PREFIX_SIZE, index, false)
  return nonce
}

/** Splits plaintext into frame-sized slices, the per-chunk loop's inner shape. */
export function frameSlices(
  plaintext: Uint8Array,
  startIndex: bigint,
): Array<{ index: bigint; last: boolean; data: Uint8Array }> {
  const out: Array<{ index: bigint; last: boolean; data: Uint8Array }> = []
  let index = startIndex
  for (let off = 0; off < plaintext.length; off += FRAME_PLAINTEXT_MAX) {
    const end = Math.min(off + FRAME_PLAINTEXT_MAX, plaintext.length)
    out.push({ index, last: end === plaintext.length, data: plaintext.subarray(off, end) })
    index++
  }
  return out
}

/** Opens a stream of concatenated frames, verifying counters and the last flag. */
export async function openStream(
  key: CryptoKey,
  stream: Uint8Array,
  startIndex: bigint,
  shareID: string,
  purpose: Purpose,
): Promise<Uint8Array> {
  const chunks: Uint8Array[] = []
  let index = startIndex
  let off = 0
  while (off < stream.length) {
    let end = off + FRAME_PLAINTEXT_MAX + FRAME_OVERHEAD
    if (end > stream.length) end = stream.length
    const frame = stream.subarray(off, end)
    if (frame.length < HEADER_SIZE) {
      throw new Error('trailing bytes are too short to be a frame, the stream is corrupt')
    }
    const last = end === stream.length
    if (frame[0] !== FORMAT_VERSION) {
      throw new Error(`unknown frame version ${frame[0]}`)
    }
    const counter = new DataView(frame.buffer, frame.byteOffset + 1 + NONCE_PREFIX_SIZE, 8).getBigUint64(
      0,
      false,
    )
    if (counter !== index) {
      throw new Error(`frame out of order, got ${counter} want ${index}`)
    }
    const pt = new Uint8Array(
      await globalThis.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: buf(frame.subarray(1, HEADER_SIZE)),
          additionalData: buf(aad(shareID, purpose, index, last)),
          tagLength: 128,
        },
        key,
        buf(frame.subarray(HEADER_SIZE)),
      ),
    )
    chunks.push(pt)
    off = end
    index++
  }
  const total = chunks.reduce((n, c) => n + c.length, 0)
  const out = new Uint8Array(total)
  let pos = 0
  for (const c of chunks) {
    out.set(c, pos)
    pos += c.length
  }
  return out
}

/** The URL fragment is the whole key: 43 canonical base64url characters. */
export function encodeFragmentKey(master: Uint8Array): string {
  if (master.length !== KEY_SIZE) {
    throw new Error(`master key must be ${KEY_SIZE} bytes, got ${master.length}`)
  }
  const bytes = new Uint8Array(master)
  const s = base64urlEncode(bytes)
  if (s.length !== FRAGMENT_LENGTH) throw new Error('fragment length drifted')
  return s
}

export function decodeFragmentKey(fragment: string): Uint8Array {
  if (fragment.length !== FRAGMENT_LENGTH) {
    throw new Error(`link key must be ${FRAGMENT_LENGTH} characters, got ${fragment.length}`)
  }
  if (/[+/=]/.test(fragment)) throw new Error('link key is not URL safe base64')
  const bytes = base64urlDecode(fragment)
  if (bytes.length !== KEY_SIZE) throw new Error('link key decoded to the wrong length')
  if (encodeFragmentKey(bytes) !== fragment) throw new Error('link key is not canonical base64url')
  return bytes
}

function base64urlEncode(bytes: Uint8Array): string {
  let s = btoa(String.fromCharCode(...bytes))
  s = s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  return s
}

function base64urlDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/** Generates the 32 byte master key. CSPRNG only. */
export function generateMasterKey(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(KEY_SIZE))
}
