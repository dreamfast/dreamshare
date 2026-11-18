import { describe, expect, it } from 'vitest'
import { planParts, ciphertextSize } from './pipeline'

describe('planParts', () => {
  it('small file is a single part', () => {
    const parts = planParts(1_000, 32 << 20)
    expect(parts).toEqual([{ number: 1, offset: 0, plaintextLength: 1000 }])
  })

  it('exactly one chunk is a single part', () => {
    const chunk = 32 << 20
    expect(planParts(chunk, chunk)).toHaveLength(1)
  })

  it('above one chunk is always two or more parts', () => {
    const chunk = 32 << 20
    const parts = planParts(chunk + 1, chunk)
    expect(parts.length).toBe(2)
    expect(parts[0]?.plaintextLength).toBe(chunk)
    expect(parts[1]?.plaintextLength).toBe(1)
  })

  it('a several chunk file splits on whole frame boundaries', () => {
    const chunk = 5 * (1 << 20) // 5 MiB, not frame aligned
    const size = 3 * chunk + 12345
    const parts = planParts(size, chunk)
    for (let i = 0; i < parts.length - 1; i++) {
      const p = parts[i]
      expect((p?.plaintextLength ?? 0) % (1 << 20)).toBe(0)
    }
    const covered = parts.reduce((n, p) => n + p.plaintextLength, 0)
    expect(covered).toBe(size)
    // offsets are contiguous
    let off = 0
    for (const p of parts) {
      expect(p.offset).toBe(off)
      off += p.plaintextLength
    }
  })

  it('refuses chunks below the storage part minimum', () => {
    expect(() => planParts(10_000_000, 1_000_000)).toThrow()
  })

  it('empty file plans no parts', () => {
    expect(planParts(0, 32 << 20)).toEqual([])
  })
})

describe('ciphertextSize', () => {
  it('adds 29 bytes per frame', () => {
    expect(ciphertextSize(1)).toBe(30)
    expect(ciphertextSize(1 << 20)).toBe((1 << 20) + 29)
    expect(ciphertextSize((1 << 20) + 1)).toBe((1 << 20) + 1 + 58)
  })
})
