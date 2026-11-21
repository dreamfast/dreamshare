import { expect, test } from '@playwright/test'
import { openSync, writeSync, closeSync } from 'node:fs'

// an interrupted send continues from the recorded parts. the netlog is
// the witness: after the reload the part numbers keep climbing, nothing
// already stored is sent twice.
test('a reload mid upload resumes instead of restarting', async ({ page }) => {
  const mib = 1024 * 1024
  const big = '/tmp/dreamshare-e2e-resume.bin'
  const fh = openSync(big, 'w')
  const filler = Buffer.alloc(mib, 5)
  for (let i = 0; i < 100; i++) writeSync(fh, filler)
  closeSync(fh)

  const partNums: number[] = []
  page.on('response', (r) => {
    const m = r.url().match(/\/api\/sessions\/[^/]+\/parts\/(\d+)$/)
    if (m) partNums.push(Number(m[1]))
  })

  await page.goto('/')
  await page.getByRole('button', { name: 'New share' }).click()
  await page.getByLabel('title').fill('resume me')
  await page.locator('input.file-input').setInputFiles(big)
  await page.getByRole('button', { name: 'Share', exact: true }).click()
  await expect(page).toHaveURL(/\/sending/)

  // let some parts land, then kill the page exactly like an accident
  await page.waitForResponse((r) => /\/api\/sessions\/[^/]+\/parts\/3$/.test(r.url()) && r.status() === 200, {
    timeout: 60_000,
  })
  await page.reload()
  await expect(page).toHaveURL(/\/sending/)

  const beforeReload = Math.max(...partNums)

  // the continuation card, the same file picked again
  await expect(page.getByText('An interrupted send can continue')).toBeVisible()
  await page.locator('.resume-pick input[type=file]').setInputFiles(big)
  await expect(page).toHaveURL(/\/uploaded/, { timeout: 120_000 })

  // nothing already sent was sent again
  const after = partNums.slice(partNums.indexOf(beforeReload) + 1)
  expect(after.length).toBeGreaterThan(0)
  for (const n of after) {
    expect(n).toBeGreaterThan(beforeReload - 1)
  }

  // and the share is whole: the recipient opens it
  const link = await page.locator('code.link').first().textContent()
  const ctx = await page.context().browser()!.newContext()
  const rec = await ctx.newPage()
  await rec.goto(link!)
  await expect(rec.getByText('dreamshare-e2e-resume.bin')).toBeVisible({ timeout: 30_000 })
  await ctx.close()
})
