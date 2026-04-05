import { defineConfig, devices } from '@playwright/test';

/**
 * Live E2E test configuration
 *
 * Runs Playwright tests against a real Kraken server instance.
 * The server must be started separately before running tests.
 *
 * Usage:
 *   # Terminal 1: Start server
 *   cargo run -p server -- --http-port 8080 --grpc-port 50051 --db-path :memory: --insecure
 *
 *   # Terminal 2: Run live tests
 *   cd kraken-web && npx playwright test --config=playwright.live.config.ts
 */
export default defineConfig({
  testDir: './e2e-live',
  fullyParallel: false, // Sequential for C2 state consistency
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  reporter: [
    ['list'],
    ['html', { outputFolder: 'playwright-live-report', open: 'never' }],
  ],
  timeout: 60000, // Longer timeout for live tests

  use: {
    baseURL: process.env.KRAKEN_WEB_URL || 'http://localhost:3003',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    actionTimeout: 15000,
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  // Start web dev server (proxies to backend)
  webServer: {
    command: 'npm run dev -- --port 3003',
    url: 'http://localhost:3003',
    reuseExistingServer: !process.env.CI,
    timeout: 30000,
    env: {
      // Vite proxy will forward /api to the backend
      VITE_API_URL: process.env.KRAKEN_GRPC_URL || 'http://localhost:50051',
    },
  },
});
