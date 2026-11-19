import { describe, expect, it } from 'vitest'
import { generateMasterKey } from '../crypto/frame'
import { sealManifest, openManifest, openCheck } from './manifest'

describe('manifest', () => {
  it('round trips with the title and files inside', async () => {
    const master = generateMasterKey()
    const shareID = 'mshare0000000000000000'
    const manifest = {
      title: 'contract',
      body: 'see **attached**',
      files: [
        {
          id: 'file000000000000000000a',
          name: 'a.pdf',
          mime: 'application/pdf',
          size: 1234,
          sha256: 'ab'.repeat(32),
        },
      ],
    }
    const blobs = await sealManifest(master, shareID, manifest)
    expect(blobs.checkCt.length).toBe(45)
    const opened = await openManifest(master, shareID, blobs.manifestCt)
    expect(opened.title).toBe('contract')
    expect(opened.files[0]?.name).toBe('a.pdf')
  })

  it('the check blob opens with the right key and fails with another', async () => {
    const master = generateMasterKey()
    const other = generateMasterKey()
    const shareID = 'mshare0000000000000000'
    const blobs = await sealManifest(master, shareID, { title: 't', body: '', files: [] })
    expect(await openCheck(master, shareID, blobs.checkCt)).not.toBeNull()
    expect(await openCheck(other, shareID, blobs.checkCt)).toBeNull()
  })

  it('a wrong share id fails to open the manifest', async () => {
    const master = generateMasterKey()
    const blobs = await sealManifest(master, 'shareAAAAAAAAAAAAAAAAA1', { title: 't', body: '', files: [] })
    await expect(openManifest(master, 'shareBBBBBBBBBBBBBBBBB2', blobs.manifestCt)).rejects.toThrow()
  })
})
