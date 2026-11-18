import jsQR from 'jsqr'
import { describe, expect, test } from 'vitest'
import { buildThemedQr, themedMatrix } from './qr'

// jsQR takes an rgba buffer, so the matrix is rasterised in pure js with
// no canvas: this decodes exactly what the svg draws, logo pad included
function rasterise(m: ReturnType<typeof themedMatrix>, scale = 8, quiet = 4): Uint8ClampedArray {
  const size = (m.count + quiet * 2) * scale
  const buf = new Uint8ClampedArray(size * size * 4)
  for (let i = 0; i < buf.length; i += 4) {
    buf[i] = 255
    buf[i + 1] = 255
    buf[i + 2] = 255
    buf[i + 3] = 255
  }
  for (let r = 0; r < m.count; r++) {
    for (let c = 0; c < m.count; c++) {
      if (!m.dark(r, c)) continue
      const dark = [52, 71, 97, 255]
      for (let y = 0; y < scale; y++) {
        for (let x = 0; x < scale; x++) {
          const px = ((quiet + r) * scale + y) * size + (quiet + c) * scale + x
          buf.set(dark, px * 4)
        }
      }
    }
  }
  return buf
}

const links = [
  'https://share.dreamfast.solutions/s/89f2a4bc01efghijkl0123#k_9xL4qP_zM71oA89dE2wTvY6bAx9cQ',
  'https://localhost:8080/s/AbCdeFgHiJkLmNoPqRsT12#k_9xL4qP_zM71oA89dE2wTvY6bAx9cQ',
]

describe('themed qr', () => {
  for (const link of links) {
    test(`logo pad qr still decodes: ${link.slice(0, 40)}…`, () => {
      const m = themedMatrix(link)
      const scale = 8
      const quiet = 4
      const size = (m.count + quiet * 2) * scale
      const res = jsQR(rasterise(m, scale, quiet), size, size)
      expect(res?.data).toBe(link)
    })
  }

  test('pad stays under a quarter of the grid', () => {
    for (const link of links) {
      const m = themedMatrix(link)
      expect(m.pad.size).toBeLessThanOrEqual(Math.ceil(m.count * 0.25))
    }
  })

  test('svg carries the logo and the brand colour', () => {
    const svg = buildThemedQr(links[0]!)
    expect(svg).toContain('/img/logo.png')
    expect(svg).toContain('#344761')
    expect(svg).toContain('rx="0.3"')
  })
})
