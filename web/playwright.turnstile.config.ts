import { defineConfig } from '@playwright/test'

// A second e2e surface: the server runs with the human check enforced,
// and the third-party script is replaced by a stub through the browser's
// route layer. the regression this guards is real: the widget once never
// rendered because its watcher ran before bootstrap landed.
export default defineConfig({
  testDir: './e2e',
  testMatch: 'turnstile-gate.test.ts',
  timeout: 60_000,
  workers: 1,
  reporter: [['line']],
  use: { baseURL: 'http://127.0.0.1:8902' },
  webServer: {
    command: '../bin/dreamshare',
    port: 8902,
    timeout: 30_000,
    reuseExistingServer: true,
    env: {
      APP_ENV: 'dev',
      LISTEN_ON: '127.0.0.1:8902',
      SQLITE_PATH: '/tmp/dreamshare-e2e-turnstile.db',
      TURNSTILE_MODE: 'required',
      TURNSTILE_SITE_KEY: 'e2e-site-key-0123456789',
      TURNSTILE_SECRET: 'e2e-secret-0123456789abcdef',
      CHUNK_MIN_BYTES: '5242880',
      CHUNK_MAX_BYTES: '6291456',
      B2_ENDPOINT: 'http://localhost:9000',
      B2_REGION: 'us-west-002',
      B2_BUCKET: 'dreamshare',
      B2_KEY_ID: 'e2e',
      B2_APPLICATION_KEY: 'e2e-application-key',
      DREAMSHARE_FAKE_STORAGE: '1',
    },
  },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
})
