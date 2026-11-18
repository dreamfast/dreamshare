// The upload pipeline: slice, seal frames, hash, ship. Frame sealing lives
// in the crypto twin, this file owns chunk planning and the part loop.

import {
  FRAME_PLAINTEXT_MAX,
  FRAME_OVERHEAD,
  deriveSubkey,
  sealFrame,
  subkeyInfo,
  newNoncePrefix,
  aad,
  type Purpose,
} from '../crypto/frame'

export interface PartPlan {
  number: number
  offset: number
  plaintextLength: number
}

// planParts splits a file into whole-frame parts. Every part except the last
// is a full chunk, which keeps every non-last part at or above the 5 MB
// storage minimum and means a file only enters the multipart path when it
// exceeds one chunk, so a one part upload can never happen.
export function planParts(fileSize: number, chunkBytes: number, frameSize = FRAME_PLAINTEXT_MAX): PartPlan[] {
  if (fileSize <= 0) return []
  if (chunkBytes < 5_000_000) throw new Error('chunk size below the 5 MB part minimum')
  const parts: PartPlan[] = []
  let offset = 0
  let number = 1
  while (offset < fileSize) {
    const len = Math.min(chunkBytes, fileSize - offset)
    // frames must divide the part exactly except the final short frame,
    // clamp the part length down to a whole frame boundary when it is not
    // the last part
    if (offset + len < fileSize) {
      const frames = Math.floor(len / frameSize)
      if (frames < 1) throw new Error('chunk smaller than one frame')
      const whole = frames * frameSize
      if (whole < 5_000_000) {
        // storage refuses non-last parts below 5,000,000 bytes, so a chunk
        // config that cannot produce such a part is refused here
        throw new Error(`chunk config produces a ${whole} byte non-last part, below the 5 MB minimum`)
      }
      parts.push({ number, offset, plaintextLength: whole })
      offset += whole
      number++
      continue
    }
    parts.push({ number, offset, plaintextLength: len })
    offset += len
    number++
  }
  // a single part at or below one chunk goes as one plain PUT, a file above
  // one chunk always yields at least two parts
  return parts
}

export function ciphertextSize(plaintextLength: number, frameSize = FRAME_PLAINTEXT_MAX): number {
  const frames = Math.ceil(plaintextLength / frameSize)
  return plaintextLength + frames * FRAME_OVERHEAD
}

export interface SealResult {
  ciphertext: Uint8Array
  frameCount: number
}

// sealPart seals one part's plaintext into frames. The frame counter runs
// across the whole file, so the caller passes the starting index from the
// plan. Only the final frame of the final part carries the last flag.
export async function sealPart(
  masterKey: Uint8Array,
  shareID: string,
  fileID: string,
  noncePrefix: Uint8Array,
  startIndex: bigint,
  plaintext: Uint8Array,
  isLastPart: boolean,
  frameSize = FRAME_PLAINTEXT_MAX,
): Promise<SealResult> {
  const key = await deriveSubkey(masterKey, subkeyInfo('file' as Purpose, fileID))
  const frames: Uint8Array[] = []
  let index = startIndex
  let off = 0
  while (off < plaintext.length) {
    const end = Math.min(off + frameSize, plaintext.length)
    const last = isLastPart && end === plaintext.length
    const frame = await sealFrame(
      key,
      noncePrefix,
      index,
      plaintext.subarray(off, end),
      shareID,
      'file',
      last,
    )
    frames.push(frame)
    index++
    off = end
  }
  const total = frames.reduce((n, f) => n + f.length, 0)
  const out = new Uint8Array(total)
  let pos = 0
  for (const f of frames) {
    out.set(f, pos)
    pos += f.length
  }
  return { ciphertext: out, frameCount: frames.length }
}

export function startingIndex(part: PartPlan, frameSize = FRAME_PLAINTEXT_MAX): bigint {
  return BigInt(Math.floor(part.offset / frameSize))
}

export async function freshNoncePrefix(): Promise<Uint8Array> {
  return newNoncePrefix()
}

// frameAAD re-exports the canonical AAD builder for tests.
export { aad, deriveSubkey, subkeyInfo }
