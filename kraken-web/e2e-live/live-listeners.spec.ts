import { test, expect } from '@playwright/test';

/**
 * Live E2E tests for Listeners
 *
 * Tests listener creation and management against a running server.
 */

test.beforeEach(async ({ page }) => {
  await page.goto('/');
  await page.evaluate(() => {
    localStorage.setItem('kraken-auth', JSON.stringify({
      state: { token: 'test-operator-token', isAuthenticated: true },
      version: 0
    }));
  });
});

test.describe('Live Listeners', () => {
  test('listeners page loads', async ({ page }) => {
    await page.goto('/listeners');

    await expect(page.getByRole('heading', { name: 'Listeners' })).toBeVisible({ timeout: 15000 });
    await expect(page.getByRole('button', { name: 'Create Listener' })).toBeVisible();
  });

  test('can open create listener modal', async ({ page }) => {
    await page.goto('/listeners');
    await expect(page.getByRole('heading', { name: 'Listeners' })).toBeVisible({ timeout: 15000 });

    await page.getByRole('button', { name: 'Create Listener' }).click();

    // Modal should open
    await expect(page.getByRole('heading', { name: 'Create Listener' })).toBeVisible();

    // Form fields
    await expect(page.getByLabel('Protocol')).toBeVisible();
    await expect(page.getByLabel(/Bind Address/i)).toBeVisible();
    await expect(page.getByLabel(/Port/i)).toBeVisible();
  });

  test('can fill listener form', async ({ page }) => {
    await page.goto('/listeners');
    await page.getByRole('button', { name: 'Create Listener' }).click();

    await expect(page.getByRole('heading', { name: 'Create Listener' })).toBeVisible();

    // Fill form
    await page.getByLabel(/Bind Address/i).fill('0.0.0.0');
    await page.getByLabel(/Port/i).fill('8443');

    // Cancel to avoid actually creating
    await page.getByRole('button', { name: 'Cancel' }).click();
    await expect(page.getByRole('heading', { name: 'Create Listener' })).not.toBeVisible();
  });
});
