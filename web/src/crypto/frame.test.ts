// Twin tests plus the Go direction of the interop pair. The Go suite writes
// fixtures-go.json, this suite opens those frames with the browser API and
// byte compares. If either side drifts, one of the two suites goes red.
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import {
  FRAME_PLAINTEXT_MAX,
  FRAME_OVERHEAD,
  FRAGMENT_LENGTH,
  aad,
  decodeFragmentKey,
  deriveSubkey,
  deriveWorkingKey,
  encodeFragmentKey,
  frameSlices,
  generateMasterKey,
  newNoncePrefix,
  openStream,
  sealFrame,
  subkeyInfo,
} from './frame'

const SHARE = 'twintest000000000000'

async function sealAll(
  key: CryptoKey,
  prefix: Uint8Array,
  shareID: string,
  purpose: 'file',
  pt: Uint8Array,
): Promise<Uint8Array> {
  const slices = frameSlices(pt, 0n)
  const frames: Uint8Array[] = []
  for (const s of slices) {
    frames.push(await sealFrame(key, prefix, s.index, s.data, shareID, purpose, s.last))
  }
  const total = frames.reduce((n, f) => n + f.length, 0)
  const out = new Uint8Array(total)
  let pos = 0
  for (const f of frames) {
    out.set(f, pos)
    pos += f.length
  }
  return out
}

describe('fragment key', () => {
  it('round trips and rejects garbage', () => {
    const master = generateMasterKey()
    const frag = encodeFragmentKey(master)
    expect(frag).toHaveLength(FRAGMENT_LENGTH)
    expect(decodeFragmentKey(frag)).toEqual(master)
    expect(() => decodeFragmentKey(frag.slice(0, 42))).toThrow()
    expect(() => decodeFragmentKey(frag + 'A')).toThrow()
    const forced = frag.slice(0, 5) + '+' + frag.slice(6)
    expect(() => decodeFragmentKey(forced)).toThrow()
  })
})

describe('frame round trip', () => {
  const sizes = [
    0,
    1,
    1000,
    FRAME_PLAINTEXT_MAX - 1,
    FRAME_PLAINTEXT_MAX,
    FRAME_PLAINTEXT_MAX + 1,
    2 * FRAME_PLAINTEXT_MAX + 5,
  ]
  for (const size of sizes) {
    it(`size ${size}`, { timeout: 30000 }, async () => {
      const master = generateMasterKey()
      const key = await deriveSubkey(master, subkeyInfo('file', 'f1'))
      const prefix = newNoncePrefix()
      const pt = new Uint8Array(size)
      for (let i = 0; i < size; i++) pt[i] = i % 251
      const ct = await sealAll(key, prefix, SHARE, 'file', pt)
      const wantFrames = Math.ceil(size / FRAME_PLAINTEXT_MAX)
      expect(ct.length).toBe(size + wantFrames * FRAME_OVERHEAD)
      const back = await openStream(key, ct, 0n, SHARE, 'file')
      expect(back).toEqual(pt)
    })
  }
})

describe('resume shape', () => {
  it('round trips a stream sealed from a nonzero counter', { timeout: 30000 }, async () => {
    const master = generateMasterKey()
    const key = await deriveSubkey(master, subkeyInfo('file', 'fr'))
    const prefix = newNoncePrefix()
    const head = new Uint8Array(FRAME_PLAINTEXT_MAX)
    const first = await sealFrame(key, prefix, 0n, head, SHARE, 'file', false)
    const second = await sealFrame(
      key,
      prefix,
      1n,
      new TextEncoder().encode('resumed tail'),
      SHARE,
      'file',
      true,
    )
    const stream = new Uint8Array(first.length + second.length)
    stream.set(first, 0)
    stream.set(second, first.length)
    const opened = await openStream(key, stream, 0n, SHARE, 'file')
    const want = new Uint8Array(head.length + 12)
    want.set(head, 0)
    want.set(new TextEncoder().encode('resumed tail'), head.length)
    expect(opened).toEqual(want)
  })
})

describe('tamper rejection', () => {
  it('rejects a truncated stream', async () => {
    const master = generateMasterKey()
    const key = await deriveSubkey(master, subkeyInfo('file', 'ft'))
    const prefix = newNoncePrefix()
    const ct = await sealAll(key, prefix, SHARE, 'file', new Uint8Array(FRAME_PLAINTEXT_MAX + 10))
    await expect(openStream(key, ct.subarray(0, ct.length - 1), 0n, SHARE, 'file')).rejects.toThrow()
  })

  it('rejects a flipped ciphertext byte', async () => {
    const master = generateMasterKey()
    const key = await deriveSubkey(master, subkeyInfo('file', 'fx'))
    const prefix = newNoncePrefix()
    const ct = await sealAll(key, prefix, SHARE, 'file', new TextEncoder().encode('attack at dawn'))
    ct[ct.length - 1] = (ct[ct.length - 1] ?? 0) ^ 1
    await expect(openStream(key, ct, 0n, SHARE, 'file')).rejects.toThrow()
  })

  it('rejects the wrong share id in the AAD', async () => {
    const master = generateMasterKey()
    const key = await deriveSubkey(master, subkeyInfo('file', 'fx'))
    const prefix = newNoncePrefix()
    const ct = await sealAll(key, prefix, SHARE, 'file', new TextEncoder().encode('x'))
    await expect(openStream(key, ct, 0n, 'other-share', 'file')).rejects.toThrow()
    await expect(openStream(key, ct, 0n, SHARE, 'manifest')).rejects.toThrow()
  })

  it('rejects a reordered stream', async () => {
    const master = generateMasterKey()
    const key = await deriveSubkey(master, subkeyInfo('file', 'fx'))
    const prefix = newNoncePrefix()
    const pt = new Uint8Array(2 * FRAME_PLAINTEXT_MAX)
    const ct = await sealAll(key, prefix, SHARE, 'file', pt)
    const stride = FRAME_PLAINTEXT_MAX + FRAME_OVERHEAD
    const swapped = new Uint8Array(ct.length)
    swapped.set(ct.subarray(stride, 2 * stride), 0)
    swapped.set(ct.subarray(0, stride), stride)
    await expect(openStream(key, swapped, 0n, SHARE, 'file')).rejects.toThrow()
  })
})

describe('AAD canonical form', () => {
  it('matches the documented encoding', () => {
    const got = aad('share1', 'file', 7n, true)
    const want = new Uint8Array([
      ...new TextEncoder().encode('ds1\0share1\0file\0'),
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      7,
      1,
    ])
    expect(got).toEqual(want)
  })
})

describe('Go interop', () => {
  it('opens Go generated fixtures', async () => {
    const path = fileURLToPath(new URL('../../../internal/crypto/testdata/fixtures-go.json', import.meta.url))
    const doc = JSON.parse(readFileSync(path, 'utf8')) as {
      format: string
      vectors: Array<{
        name: string
        share_id: string
        purpose: 'file' | 'manifest' | 'check' | 'title'
        id: string
        master_key: string
        nonce_prefix: string
        plaintext: string
        ciphertext: string
      }>
    }
    expect(doc.format).toBe('ds1')
    expect(doc.vectors.length).toBeGreaterThanOrEqual(6)
    for (const v of doc.vectors) {
      const master = decodeFragmentKey(v.master_key)
      const key = await deriveSubkey(master, subkeyInfo(v.purpose, v.id))
      const ct = Uint8Array.from(Buffer.from(v.ciphertext, 'base64'))
      const prefix = Uint8Array.from(Buffer.from(v.nonce_prefix, 'base64'))
      if (ct.length >= 13) {
        expect(ct[1]).toBe(prefix[0])
      }
      const opened = await openStream(key, ct, 0n, v.share_id, v.purpose)
      expect(Buffer.from(opened).toString('base64')).toBe(v.plaintext)
    }
  })
})

describe('deriveWorkingKey', () => {
  const master = new Uint8Array(32).fill(7)
  const salt = new Uint8Array(16).fill(3)

  it('is deterministic for the same inputs', async () => {
    const a = await deriveWorkingKey(master, 'hunter2', salt, 100_000)
    const b = await deriveWorkingKey(master, 'hunter2', salt, 100_000)
    expect(a).toEqual(b)
    expect(a.length).toBe(32)
  })

  it('differs per passphrase, per salt and from the raw master', async () => {
    const base = await deriveWorkingKey(master, 'hunter2', salt, 100_000)
    const otherPass = await deriveWorkingKey(master, 'hunter3', salt, 100_000)
    const otherSalt = await deriveWorkingKey(master, 'hunter2', new Uint8Array(16).fill(9), 100_000)
    expect(Buffer.from(otherPass).equals(Buffer.from(base))).toBe(false)
    expect(Buffer.from(otherSalt).equals(Buffer.from(base))).toBe(false)
    expect(Buffer.from(base).equals(Buffer.from(master))).toBe(false)
  })
})
