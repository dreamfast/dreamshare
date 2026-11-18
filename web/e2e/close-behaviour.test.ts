import { expect, test } from '@playwright/test'

// close, cancel and esc must all land on / with the circle back. the
// close click used to bubble into a wrapper handler that flipped the
// form straight back open
test('close, cancel and esc all close the form', async ({ page }) => {
  await page.goto('/')
  const open = () => page.getByRole('button', { name: 'New share' }).click()

  await open()
  await expect(page).toHaveURL('/upload')
  await page.keyboard.press('Escape')
  await expect(page).toHaveURL('/')
  await expect(page.getByRole('button', { name: 'New share' })).toBeVisible()

  await open()
  await expect(page).toHaveURL('/upload')
  await page.getByRole('button', { name: 'Close' }).click()
  await expect(page).toHaveURL('/')
  await expect(page.getByRole('button', { name: 'New share' })).toBeVisible()

  await open()
  await expect(page).toHaveURL('/upload')
  await page.getByRole('button', { name: 'Cancel' }).click()
  await expect(page).toHaveURL('/')
  await expect(page.getByRole('button', { name: 'New share' })).toBeVisible()
})
