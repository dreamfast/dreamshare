import { expect, test } from '@playwright/test'

test('a passphrase share gates the recipient until the password opens it', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: 'New share' }).click()
  await page.getByLabel('title').fill('locked share')
  await page.locator('input[type=password]').first().fill('swordfish')
  await page.locator('input[type=file]').setInputFiles({
    name: 'secret.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('only with the password'),
  })
  await page.getByRole('button', { name: 'Share', exact: true }).click()
  await expect(page.getByText('locked share').or(page.getByText('Your share is ready'))).toBeVisible()
  await expect(page).toHaveURL(/\/uploaded/, { timeout: 60_000 })
  const link = await page.locator('code.link').first().textContent()
  expect(link).toBeTruthy()

  const recipient = await page.context().browser()!.newContext()
  const rec = await recipient.newPage()
  await rec.goto(link!)

  // the gate: no files, no message, the lock screen
  await expect(rec.getByRole('heading', { name: 'This share needs its password' })).toBeVisible()
  await expect(rec.getByText('secret.txt')).toHaveCount(0)

  // a wrong password is refused without killing the page
  await rec.getByLabel('Share password').fill('wrongpass')
  await rec.getByRole('button', { name: 'Open' }).click()
  await expect(rec.getByText('That password did not open the share. Try again.')).toBeVisible()

  // the right one opens the share and the file downloads clean
  await rec.getByLabel('Share password').fill('swordfish')
  await rec.getByRole('button', { name: 'Open' }).click()
  await expect(rec.getByText('secret.txt')).toBeVisible({ timeout: 15_000 })
  await rec.getByRole('button', { name: 'Download', exact: true }).click()
  await expect(rec.getByRole('button', { name: 'Verified', exact: true })).toBeVisible({
    timeout: 30_000,
  })
  await recipient.close()
})
