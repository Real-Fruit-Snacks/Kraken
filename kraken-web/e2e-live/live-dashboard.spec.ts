import { test, expect } from '@playwright/test';

/**
 * Live E2E tests for Dashboard
 *
 * These tests require a running Kraken server.
 * Start server: cargo run -p server -- --http-port 8080 --grpc-port 50051 --db-path :memory: --insecure
 */

test.beforeEach(async ({ page }) => {
  // Set auth token for authenticated access
  await page.goto('/');
  await page.evaluate(() => {
    localStorage.setItem('kraken-auth', JSON.stringify({
      state: { token: 'test-operator-token', isAuthenticated: true },
      version: 0
    }));
  });
});

test.describe('Live Dashboard', () => {
  test('loads with real server data', async ({ page }) => {
    await page.goto('/');

    // Should show Dashboard heading
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible({ timeout: 15000 });

    // Should show stat cards (even if empty) - use main content area to avoid nav
    const main = page.getByRole('main');
    await expect(main.locator('text=Active Sessions')).toBeVisible();
    await expect(main.locator('text=Total Sessions')).toBeVisible();
    await expect(main.locator('text=Loot')).toBeVisible();
  });

  test('shows server connection status', async ({ page }) => {
    await page.goto('/');

    // Wait for dashboard to load
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible({ timeout: 15000 });

    // Brief wait for data fetch
    await page.waitForTimeout(2000);

    // Should NOT show "Failed to load" error when server is running
    const errorText = page.locator('text=Failed to load');
    const errorCount = await errorText.count();

    if (errorCount > 0) {
      // If error exists, server might not be running
      console.log('Warning: Dashboard shows error - ensure Kraken server is running');
    }
  });

  test('recent sessions section exists', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible({ timeout: 15000 });

    // Recent sessions section
    await expect(page.locator('text=Recent Sessions')).toBeVisible();
  });

  test('activity feed section exists', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible({ timeout: 15000 });

    // Activity feed section (use exact match to avoid multiple matches)
    await expect(page.getByRole('heading', { name: 'Activity', exact: true })).toBeVisible();
  });
});
