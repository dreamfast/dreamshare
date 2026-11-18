// Generates testdata/fixtures.json for the Go interop test using Node's
// WebCrypto, the same API the browser uses. The vectors are deterministic
// except the keys, and nobody hand edits the output.
//
//   node scripts/gen-fixtures.mjs
import { webcrypto as crypto } from 'node:crypto'
import { writeFileSync, mkdirSync } from 'node:fs'

const FORMAT_NAME = 'ds1'
const FORMAT_VERSION = 0x01
const FRAME_PLAINTEXT_MAX = 1 << 20
const NONCE_PREFIX_SIZE = 4

const b64 = (buf) => Buffer.from(buf).toString('base64')
const b64url = (buf) => Buffer.from(buf).toString('base64url')

async function deriveSubkey(master, info) {
  const key = await crypto.subtle.importKey('raw', master, 'HKDF', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: Buffer.from(info) },
    key,
    256,
  )
  return new Uint8Array(bits)
}

function subkeyInfo(purpose, id) {
  return id ? `dreamshare:${purpose}:${id}` : `dreamshare:${purpose}`
}

function aad(shareID, purpose, index, last) {
  const parts = [
    Buffer.from(FORMAT_NAME),
    Buffer.from([0]),
    Buffer.from(shareID),
    Buffer.from([0]),
    Buffer.from(purpose),
    Buffer.from([0]),
  ]
  const idx = Buffer.alloc(8)
  idx.writeBigUInt64BE(BigInt(index))
  parts.push(idx, Buffer.from([last ? 1 : 0]))
  return Buffer.concat(parts)
}

async function sealStream(subkey, noncePrefix, startIndex, plaintext, shareID, purpose) {
  const key = await crypto.subtle.importKey('raw', subkey, 'AES-GCM', false, ['encrypt'])
  const frames = []
  let index = startIndex
  for (let off = 0; off < plaintext.length; off += FRAME_PLAINTEXT_MAX) {
    const end = Math.min(off + FRAME_PLAINTEXT_MAX, plaintext.length)
    const last = end === plaintext.length
    const nonce = Buffer.concat([noncePrefix, (() => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(index)); return b })()])
    const ct = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: aad(shareID, purpose, index, last), tagLength: 128 },
      key,
      plaintext.subarray(off, end),
    ))
    const frame = Buffer.concat([Buffer.from([FORMAT_VERSION]), nonce, Buffer.from(ct)])
    frames.push(frame)
    index++
  }
  return { stream: Buffer.concat(frames), frameCount: frames.length }
}

const SHARE = 'nodehare0000000000000'
const master = crypto.getRandomValues(new Uint8Array(32))
const masterFrag = b64url(master)

const cases = [
  { name: 'node-file-multiframe', purpose: 'file', id: 'nfile1', size: FRAME_PLAINTEXT_MAX + 299 },
  { name: 'node-file-single', purpose: 'file', id: 'nfile2', text: 'node single frame payload' },
  { name: 'node-file-empty', purpose: 'file', id: 'nfile3', size: 0 },
  { name: 'node-manifest', purpose: 'manifest', id: '', text: '{"title":"node manifest","files":[]}' },
  { name: 'node-check', purpose: 'check', id: '', size: 16 },
  { name: 'node-title', purpose: 'title', id: '', text: 'node title' },
]

const vectors = []
for (const c of cases) {
  // text cases must carry their real bytes, an empty buffer under a text
  // name makes the vector vacuous
  const size = c.text ? Buffer.byteLength(c.text, 'utf8') : (c.size ?? 0)
  const plaintext = Buffer.alloc(size)
  if (c.text) {
    plaintext.write(c.text, 0, 'utf8')
  } else {
    for (let i = 0; i < plaintext.length; i++) plaintext[i] = i % 251
  }
  if (size === 0 && !c.name.endsWith('empty')) throw new Error(`vector ${c.name} is unexpectedly empty`)
  const prefix = crypto.getRandomValues(new Uint8Array(NONCE_PREFIX_SIZE))
  const subkey = await deriveSubkey(master, subkeyInfo(c.purpose, c.id))
  const { stream, frameCount } = await sealStream(subkey, prefix, 0, plaintext, SHARE, c.purpose)
  vectors.push({
    name: c.name,
    share_id: SHARE,
    purpose: c.purpose,
    id: c.id,
    master_key: masterFrag,
    nonce_prefix: b64url(prefix),
    plaintext: b64(plaintext),
    ciphertext: b64(stream),
    frame_count: frameCount,
  })
}

mkdirSync(new URL('../internal/crypto/testdata/', import.meta.url), { recursive: true })
writeFileSync(
  new URL('../internal/crypto/testdata/fixtures.json', import.meta.url),
  JSON.stringify({ format: FORMAT_NAME, vectors }, null, 2) + '\n',
)
console.log(`wrote ${vectors.length} vectors for master key ${masterFrag.slice(0, 8)}…`)
