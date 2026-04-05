import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e/suites',
  testIgnore: [
    '**/accessibility.spec.ts',
    '**/collab.spec.ts',
    '**/comprehensive.spec.ts',
    '**/cross-browser.spec.ts',
    '**/defender.spec.ts',
    '**/opsec.spec.ts',
    '**/pages.spec.ts',
    '**/phase5.spec.ts',
    '**/sessions.spec.ts',
  ],
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 2 : 1,
  reporter: [
    ['list'],
    ['html', { open: 'never' }],
    ['json', { outputFile: 'playwright-report/test-results.json' }],
  ],

  use: {
    baseURL: 'http://127.0.0.1:3000',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',

    // Capture console logs
    contextOptions: {
      logger: {
        isEnabled: () => true,
        log: (name, severity, message) => console.log(`[${severity}] ${name}: ${message}`),
      },
    },
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  // Web server to start before tests
  webServer: {
    command: 'VITE_USE_CONNECT=true npm run dev',
    url: 'http://127.0.0.1:3000',
    reuseExistingServer: !process.env.CI,
    timeout: 30000,
  },
});
