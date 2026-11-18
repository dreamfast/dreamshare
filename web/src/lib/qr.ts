import qrcode from 'qrcode-generator'

// Branded QR: dark slate modules, rounded finder rings and the logo on a
// white pad in the centre. Error correction H so the pad area is
// recoverable, and the pad stays under a quarter of the grid width.
// The visual matrix lives in themedMatrix and the svg builder draws
// exactly that, so the decode test proves the shipped picture scans.

const DARK = '#344761'
const LOGO_W = 250
const LOGO_H = 169

export type ThemedMatrix = {
  count: number
  dark: (r: number, c: number) => boolean
  pad: { start: number; size: number }
}

function finderZone(r: number, c: number, n: number): 'tl' | 'tr' | 'bl' | null {
  if (r < 7 && c < 7) return 'tl'
  if (r < 7 && c >= n - 7) return 'tr'
  if (r >= n - 7 && c < 7) return 'bl'
  return null
}

// the standard finder ring pattern relative to its own 7x7 box
function finderDark(r: number, c: number): boolean {
  return r === 0 || r === 6 || c === 0 || c === 6 || (r >= 2 && r <= 4 && c >= 2 && c <= 4)
}

export function themedMatrix(link: string): ThemedMatrix {
  const qr = qrcode(0, 'H')
  qr.addData(link)
  qr.make()
  const n = qr.getModuleCount()
  const size = Math.max(5, Math.round(n * 0.22))
  const start = Math.floor((n - size) / 2)
  const pad = { start, size }
  const inPad = (r: number, c: number) =>
    r >= pad.start && r < pad.start + pad.size && c >= pad.start && c < pad.start + pad.size
  return {
    count: n,
    pad,
    dark: (r: number, c: number) => {
      const fz = finderZone(r, c, n)
      if (fz !== null) {
        // remap to the finder's own 7x7 box
        const lr = fz === 'bl' ? r - (n - 7) : r
        const lc = fz === 'tr' ? c - (n - 7) : c
        return finderDark(lr, lc)
      }
      if (inPad(r, c)) return false
      return qr.isDark(r, c)
    },
  }
}

export function buildThemedQr(link: string): string {
  const m = themedMatrix(link)
  const quiet = 3
  const total = m.count + quiet * 2
  const o = quiet
  let dots = ''
  for (let r = 0; r < m.count; r++) {
    for (let c = 0; c < m.count; c++) {
      if (finderZone(r, c, m.count)) continue
      if (m.dark(r, c)) {
        dots += `<rect x="${o + c}" y="${o + r}" width="1" height="1" rx="0.3" fill="${DARK}"/>`
      }
    }
  }
  // finder rings drawn as shapes, cleaner than per module dots
  const finder = (x: number, y: number) =>
    `<rect x="${x}" y="${y}" width="7" height="7" rx="1.8" fill="${DARK}"/>` +
    `<rect x="${x + 1}" y="${y + 1}" width="5" height="5" rx="1.2" fill="#ffffff"/>` +
    `<rect x="${x + 2}" y="${y + 2}" width="3" height="3" rx="0.8" fill="${DARK}"/>`
  const p = m.pad
  const cx = o + p.start
  const logoW = p.size * 0.86
  const logoH = (logoW * LOGO_H) / LOGO_W
  const logoX = o + p.start + (p.size - logoW) / 2
  const logoY = o + p.start + (p.size - logoH) / 2
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${total} ${total}" shape-rendering="geometricPrecision">` +
    `<rect width="${total}" height="${total}" fill="#ffffff"/>` +
    finder(o, o) +
    finder(o + m.count - 7, o) +
    finder(o, o + m.count - 7) +
    dots +
    `<rect x="${cx}" y="${o + p.start}" width="${p.size}" height="${p.size}" rx="1.6" fill="#ffffff" stroke="${DARK}" stroke-opacity="0.18" stroke-width="0.2"/>` +
    `<image href="/img/logo.png" x="${logoX}" y="${logoY}" width="${logoW}" height="${logoH}"/>` +
    `</svg>`
  )
}
