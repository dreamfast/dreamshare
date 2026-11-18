import { describe, expect, it } from 'vitest'
import { safeName } from './safename'

describe('safeName', () => {
  it('strips control characters and bidi overrides', () => {
    expect(safeName('report\u202efile.pdf')).toBe('reportfile.pdf')
    expect(safeName('a\u0000b\u007fc')).toBe('abc')
    expect(safeName('x\u2066y\u2069z\u061cw')).toBe('xyzw')
  })
  it('caps at 200 runes', () => {
    expect(safeName('a'.repeat(300)).length).toBe(200)
  })
  it('falls back when nothing survives', () => {
    expect(safeName('\u202e')).toBe('file')
  })
  it('keeps ordinary names intact', () => {
    expect(safeName('notes (final) v2.txt')).toBe('notes (final) v2.txt')
  })
})
