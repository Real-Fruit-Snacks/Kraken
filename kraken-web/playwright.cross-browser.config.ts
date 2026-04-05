import { defineConfig, devices } from '@playwright/test';

/**
 * Cross-browser testing configuration
 *
 * Run with: npx playwright test --config=playwright.cross-browser.config.ts
 *
 * Tests UI functionality across Chrome, Firefox, Safari, and mobile viewports.
 */
export default defineConfig({
  testDir: './e2e',
  testMatch: ['**/cross-browser.spec.ts', '**/accessibility.spec.ts'],
  fullyParallel: true, // Cross-browser tests can run in parallel
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 4 : 2,
  reporter: [
    ['list'],
    ['html', { open: 'never', outputFolder: 'playwright-report-cross-browser' }],
    ['json', { outputFile: 'test-results/cross-browser-results.json' }],
  ],

  use: {
    baseURL: 'http://localhost:3003',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },

  projects: [
    // Desktop browsers
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
    },

    // Mobile viewports
    {
      name: 'mobile-chrome',
      use: { ...devices['Pixel 5'] },
    },
    {
      name: 'mobile-safari',
      use: { ...devices['iPhone 13'] },
    },

    // Tablet viewport
    {
      name: 'tablet',
      use: { ...devices['iPad Pro 11'] },
    },

    // Edge (Chromium-based)
    {
      name: 'edge',
      use: { ...devices['Desktop Edge'], channel: 'msedge' },
    },
  ],

  // Web server configuration
  webServer: {
    command: 'npm run dev -- --port 3003',
    url: 'http://localhost:3003',
    reuseExistingServer: !process.env.CI,
    timeout: 60000,
  },
});
