import { expect, test } from '@playwright/test'

// The enforced path, with the third party replaced by a stub. the stub is
// routed in the browser, so the loader, the watcher and the bootstrap
// reconciliation all run the production code. the server keeps its real
// verifier: a stub token is refused fail closed, which is the assertion
// at the end of this test, not an accident.
const STUB_API = `
window.turnstile = {
  render(el, opts) {
    const host = typeof el === 'string' ? document.querySelector(el) : el;
    const d = document.createElement('div');
    d.className = 'cf-stub-widget';
    d.textContent = 'human check';
    host.appendChild(d);
    setTimeout(() => opts.callback('stub-token-000'), 150);
    return 'stub-1';
  },
  reset() {},
  remove() {},
};
`

test('the human check widget renders on the sending stage and a refused token surfaces an error', async ({
  page,
}) => {
  await page.route('**/challenges.cloudflare.com/turnstile/v0/api.js', (route) =>
    route.fulfill({ contentType: 'application/javascript', body: STUB_API }),
  )

  await page.goto('/')
  await page.getByRole('button', { name: 'New share' }).click()
  await page.getByLabel('title').fill('turnstile gate')
  await page.getByRole('button', { name: 'Share', exact: true }).click()

  await expect(page).toHaveURL(/\/sending/)
  // the card parks ready for the human check, the widget is not on the form
  await expect(page.getByRole('heading', { name: 'Ready to send' })).toBeVisible()

  // the regression: the widget mounts only after bootstrap lands, this
  // once hung forever with an empty box
  await expect(page.locator('.cf-stub-widget')).toBeVisible({ timeout: 15_000 })

  // the stub hands over a token, the real verifier refuses it, the run
  // lands in the error state rather than going quiet
  await expect(page.getByRole('heading', { name: 'Could not send' })).toBeVisible({
    timeout: 30_000,
  })
  await expect(page.getByText(/human check|token|try again/i).first()).toBeVisible()
})
