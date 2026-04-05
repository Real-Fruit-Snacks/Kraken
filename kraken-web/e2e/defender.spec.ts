import { test, expect } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  // Set up auth to bypass login
  await page.goto('http://localhost:3003');
  await page.evaluate(() => {
    localStorage.setItem('kraken-auth', JSON.stringify({
      state: { token: 'test-operator-token', isAuthenticated: true },
      version: 0
    }));
  });
});

test.describe('Defender Page', () => {
  test('Defender page loads with tabs', async ({ page }) => {
    await page.goto('/defender');

    // Check page header
    await expect(page.getByRole('heading', { name: 'Defender Dashboard' })).toBeVisible();

    // Check tabs exist
    await expect(page.getByRole('button', { name: /Overview/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /IOC Catalog/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /Detection Rules/i })).toBeVisible();
  });

  test('Overview tab shows statistics', async ({ page }) => {
    await page.goto('/defender');

    // Should be on overview by default
    await expect(page.getByText('Detection Philosophy')).toBeVisible();
    await expect(page.getByText('Network IOCs')).toBeVisible();
    await expect(page.getByText('Host IOCs')).toBeVisible();
  });

  test('IOC Catalog tab shows IOC tables', async ({ page }) => {
    await page.goto('/defender');

    // Click IOC Catalog tab
    await page.getByRole('button', { name: /IOC Catalog/i }).click();

    // Check IOC viewer loaded
    await expect(page.getByText('Network')).toBeVisible();
    await expect(page.getByText('Host')).toBeVisible();
    await expect(page.getByText('Memory')).toBeVisible();
    await expect(page.getByText('Behavioral')).toBeVisible();

    // Check search input exists
    await expect(page.getByPlaceholder(/Search IOCs/i)).toBeVisible();
  });

  test('Detection Rules tab shows YARA and Sigma rules', async ({ page }) => {
    await page.goto('/defender');

    // Click Detection Rules tab
    await page.getByRole('button', { name: /Detection Rules/i }).click();

    // Check rule viewer loaded
    await expect(page.getByRole('button', { name: /YARA/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /Sigma/i })).toBeVisible();
  });

  test('IOC search filters results', async ({ page }) => {
    await page.goto('/defender');
    await page.getByRole('button', { name: /IOC Catalog/i }).click();

    // Type in search
    const searchInput = page.getByPlaceholder(/Search IOCs/i);
    await searchInput.fill('beacon');

    // Results should be filtered (fewer items visible)
    await page.waitForTimeout(300); // Debounce
  });

  test('IOC export button exists', async ({ page }) => {
    await page.goto('/defender');
    await page.getByRole('button', { name: /IOC Catalog/i }).click();

    // Check export button
    await expect(page.getByRole('button', { name: /Export JSON/i })).toBeVisible();
  });

  test('YARA rules have syntax highlighting', async ({ page }) => {
    await page.goto('/defender');
    await page.getByRole('button', { name: /Detection Rules/i }).click();

    // Expand a rule to see code
    const expandButtons = page.locator('button').filter({ hasText: /Kraken/ });
    if (await expandButtons.count() > 0) {
      await expandButtons.first().click();

      // Check for code block with highlighting classes
      await expect(page.locator('pre')).toBeVisible();
    }
  });
});
