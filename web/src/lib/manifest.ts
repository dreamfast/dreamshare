// The manifest rides inside the share as ciphertext. The server stores it
// opaquely, only a browser holding the fragment key can read it.

import {
  deriveSubkey,
  subkeyInfo,
  sealFrame,
  openStream,
  openStream as open,
  type Purpose,
} from '../crypto/frame'

export interface ManifestFile {
  id: string
  name: string
  mime: string
  size: number
  sha256: string
}

export interface Manifest {
  title: string
  body: string
  files: ManifestFile[]
}

function toB64(bytes: Uint8Array): string {
  const s = btoa(String.fromCharCode(...bytes))
  return s
}

function fromB64(s: string): Uint8Array {
  const bin = atob(s)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

async function sealBlob(
  masterKey: Uint8Array,
  shareID: string,
  purpose: 'manifest' | 'title' | 'check',
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const key = await deriveSubkey(masterKey, subkeyInfo(purpose, ''))
  const prefix = globalThis.crypto.getRandomValues(new Uint8Array(4))
  return sealFrame(key, prefix, 0n, plaintext, shareID, purpose, true)
}

async function openBlob(
  masterKey: Uint8Array,
  shareID: string,
  purpose: Purpose,
  blob: Uint8Array,
): Promise<Uint8Array> {
  const key = await deriveSubkey(masterKey, subkeyInfo(purpose, ''))
  return open(key, blob, 0n, shareID, purpose)
}

export async function sealManifest(
  masterKey: Uint8Array,
  shareID: string,
  manifest: Manifest,
): Promise<{
  manifestCt: Uint8Array
  titleCt: Uint8Array
  checkCt: Uint8Array
  checkVerifier: Uint8Array
}> {
  const json = new TextEncoder().encode(JSON.stringify(manifest))
  const manifestCt = await sealBlob(masterKey, shareID, 'manifest', json)
  const titleCt = await sealBlob(masterKey, shareID, 'title', new TextEncoder().encode(manifest.title))
  // the check verifier is 16 fresh random bytes, fixed 45 byte blob
  const verifier = globalThis.crypto.getRandomValues(new Uint8Array(16))
  const checkCt = await sealBlob(masterKey, shareID, 'check', verifier)
  return { manifestCt, titleCt, checkCt, checkVerifier: verifier }
}

export async function openManifest(
  masterKey: Uint8Array,
  shareID: string,
  manifestCt: Uint8Array,
): Promise<Manifest> {
  const json = await openBlob(masterKey, shareID, 'manifest', manifestCt)
  return JSON.parse(new TextDecoder().decode(json)) as Manifest
}

// openCheck returns the verifier bytes to a key holder, null to anyone
// else. the hash of these bytes is the ack proof, so a wrong key both
// fails here and cannot wipe the share later.
export async function openCheck(
  masterKey: Uint8Array,
  shareID: string,
  checkCt: Uint8Array,
): Promise<Uint8Array | null> {
  try {
    const opened = await openBlob(masterKey, shareID, 'check', checkCt)
    return opened.length === 16 ? opened : null
  } catch {
    return null
  }
}

export { toB64, fromB64, openStream }
