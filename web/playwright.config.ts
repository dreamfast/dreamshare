import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: 'e2e',
  timeout: 120_000,
  use: {
    baseURL: 'http://127.0.0.1:8901',
  },
  webServer: {
    command: '../bin/dreamshare',
    port: 8901,
    timeout: 30_000,
    reuseExistingServer: true,
    env: {
      APP_ENV: 'dev',
      LISTEN_ON: '127.0.0.1:8901',
      SQLITE_PATH: '/tmp/dreamshare-e2e.db',
      TURNSTILE_MODE: 'disabled',
      // six mib chunks so the journey crosses the three token look ahead
      // window with five small parts instead of two big ones. a part must
      // be whole one mib frames and at least five million bytes, so the
      // smallest legal chunk is five frames, 5242880
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
