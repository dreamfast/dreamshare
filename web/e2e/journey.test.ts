import { expect, test } from '@playwright/test'
import { appendFileSync, closeSync, openSync, writeSync } from 'node:fs'

function watch(page: import('@playwright/test').Page, tag: string): void {
  page.on('response', async (r) => {
    if (r.url().includes('/api/') || r.url().includes('/dl/')) {
      let extra = ''
      if (r.status() >= 400) {
        try {
          extra = ' BODY=' + (await r.text()).slice(0, 120)
        } catch {
          // body already consumed
        }
      }
      appendFileSync(
        '/tmp/e2e-net.log',
        `${tag} ${r.request().method()} ${r.status()} ${r.url().replace('http://127.0.0.1:8901', '')}${extra}\n`,
      )
    }
  })
  page.on('pageerror', (e) => {
    appendFileSync('/tmp/e2e-net.log', `${tag} PAGEERR ${e.message}\n`)
  })
}

// The journey that matters: morph to form, encrypt in the browser, upload,
// open the link in a second context, decrypt, verify, ack, wipe, gone.
test('upload to wipe', async ({ page, browser }) => {
  watch(page, 'send')
  await page.goto('/')
  await expect(page.getByRole('button', { name: 'New share' })).toBeVisible()
  await expect(page.getByText('click to upload')).toBeVisible()

  await page.getByRole('button', { name: 'New share' }).click()
  await expect(page).toHaveURL('/upload')
  await expect(page.getByRole('heading', { name: 'Share something' })).toBeVisible()

  await page.getByLabel('title').fill('e2e contract')
  await page.locator('#share-message').fill('hello **recipient**')
  await page.locator('input[type=file]').setInputFiles({
    name: 'notes.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('dreamshare end to end payload'),
  })
  await page.getByRole('button', { name: 'Share', exact: true }).click()

  // the sending room owns the run: recap visible, then the success view
  await expect(page).toHaveURL(/\/sending/)
  await expect(page.getByRole('heading', { name: 'Sending your share' })).toBeVisible()
  // localhost can finish the whole send before this samples, accept either
  await expect(page.getByText('e2e contract').or(page.getByText('Your share is ready'))).toBeVisible()
  await expect(page).toHaveURL(/\/uploaded/, { timeout: 60_000 })
  // the invariant: no key, no manager token, no fragment anywhere in the url
  expect(page.url()).not.toMatch(/[?&](k|m)=/)
  expect(page.url().includes('#')).toBe(false)
  const link = await page.locator('code.link').first().textContent()
  expect(link).toMatch(/\/s\/[0-9A-Za-z]{22}#.{43}/)

  const ctx = await browser.newContext()
  const rec = await ctx.newPage()
  watch(rec, 'recv')
  // D23 and the privacy page both claim zero third-party requests on the
  // recipient page, hold that claim here
  const origins = new Set<string>()
  rec.on('request', (r) => origins.add(new URL(r.url()).origin))
  await rec.goto(link!)
  await expect(rec.getByRole('heading', { name: 'e2e contract' })).toBeVisible()
  await expect(rec.getByText('recipient')).toBeVisible()
  await expect(rec.getByText('notes.txt')).toBeVisible()

  const download = rec.waitForEvent('download')
  await rec.getByRole('button', { name: 'Download', exact: true }).click()
  const dl = await download
  const stream = await dl.createReadStream()
  const bytes = await new Promise<Buffer>((resolve) => {
    const chunks: Buffer[] = []
    stream?.on('data', (c: Buffer) => chunks.push(c))
    stream?.on('end', () => resolve(Buffer.concat(chunks)))
  })
  expect(bytes.toString('utf8')).toBe('dreamshare end to end payload')
  await expect(rec.getByRole('button', { name: /Verified/ })).toBeVisible({ timeout: 30_000 })

  // the ack wiped the burn share, reloading the link must say so
  await rec.reload()
  await expect(rec.getByText(/no longer available/i)).toBeVisible({ timeout: 30_000 })
  for (const o of origins) {
    expect(o, 'third-party request on the share page').toBe('http://127.0.0.1:8901')
  }
  await ctx.close()
})

// five parts at the small e2e chunk size: an exact multiple of the chunk
// and one part beyond the three token look ahead window, the refill that
// once handed a reused token to a later part and 403ed the upload
test('multipart across the exact chunk multiple', async ({ page, browser }) => {
  watch(page, 'mp-send')
  await page.goto('/')
  await page.getByRole('button', { name: 'New share' }).click()
  await page.getByLabel('title').fill('multipart exact multiple')

  // five exact chunks of the six mib e2e part size, 30 MB total
  const mib = 1024 * 1024
  const bigPath = '/tmp/dreamshare-e2e-big.bin'
  const fh = openSync(bigPath, 'w')
  const filler = Buffer.alloc(mib, 7)
  for (let i = 0; i < 30; i++) writeSync(fh, filler)
  closeSync(fh)
  await page.locator('input[type=file]').setInputFiles(bigPath)

  await page.getByRole('button', { name: 'Share', exact: true }).click()
  await expect(page).toHaveURL(/\/sending/)
  // per file progress is visible while the five parts stream
  await expect(
    page.getByText('dreamshare-e2e-big.bin').or(page.getByText('Your share is ready')),
  ).toBeVisible()
  await expect(page.getByText(/\d+ \/ \d+ parts/).or(page.getByText('Your share is ready'))).toBeVisible()
  await expect(page).toHaveURL(/\/uploaded/, { timeout: 180_000 })
  expect(page.url()).not.toMatch(/[?&](k|m)=/)
  expect(page.url().includes('#')).toBe(false)
  const link = await page.locator('code.link').first().textContent()
  expect(link).toBeTruthy()

  const ctx = await browser.newContext()
  const rec = await ctx.newPage()
  watch(rec, 'mp-recv')
  await rec.goto(link!)
  await expect(rec.getByRole('heading', { name: 'multipart exact multiple' })).toBeVisible({
    timeout: 60_000,
  })
  await expect(rec.getByText('big.bin')).toBeVisible()
  await ctx.close()
})

test('wrong fragment key says gone', async ({ page }) => {
  await page.goto('/s/aaaaaaaaaaaaaaaaaaaaaa#' + 'A'.repeat(43))
  await expect(page.getByText(/incomplete|no longer available/i)).toBeVisible({ timeout: 30_000 })
})
