import { expect, test } from '@playwright/test'

// cancel and esc must both land on / with the circle back. the close
// click used to bubble into a wrapper handler that flipped the form
// straight back open
test('cancel and esc both close the form', async ({ page }) => {
  await page.goto('/')
  const open = () => page.getByRole('button', { name: 'New share' }).click()

  await open()
  await expect(page).toHaveURL('/upload')
  await page.keyboard.press('Escape')
  await expect(page).toHaveURL('/')
  await expect(page.getByRole('button', { name: 'New share' })).toBeVisible()

  await open()
  await expect(page).toHaveURL('/upload')
  await page.getByRole('button', { name: 'Cancel' }).click()
  await expect(page).toHaveURL('/')
  await expect(page.getByRole('button', { name: 'New share' })).toBeVisible()
})

test('message write and preview modes', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: 'New share' }).click()
  await expect(page).toHaveURL('/upload')

  await page.locator('#share-message').fill('hello **recipient**')
  await page.getByRole('tab', { name: 'Preview' }).click()
  await expect(page.locator('.msg-preview strong', { hasText: 'recipient' })).toBeVisible()
  await page.getByRole('tab', { name: 'Write' }).click()
  await expect(page.locator('#share-message')).toHaveValue('hello **recipient**')
})
