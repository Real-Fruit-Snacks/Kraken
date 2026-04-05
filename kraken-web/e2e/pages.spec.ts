import { test, expect } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.goto('http://localhost:3003');
  await page.evaluate(() => {
    localStorage.setItem('kraken-auth', JSON.stringify({
      state: { token: 'test-operator-token', isAuthenticated: true },
      version: 0
    }));
  });
});

test('Loot page loads', async ({ page }) => {
  await page.goto('/loot');
  await expect(page.getByRole('heading', { name: 'Loot' })).toBeVisible();
  await expect(page.getByText('Export All')).toBeVisible();
});

test('Listeners page loads', async ({ page }) => {
  await page.goto('/listeners');
  await expect(page.getByRole('heading', { name: 'Listeners' })).toBeVisible();
  await expect(page.getByText('Create Listener')).toBeVisible();
});

test('Dashboard page loads', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
});

test('Operators page loads', async ({ page }) => {
  await page.goto('/operators');
  await expect(page.getByRole('heading', { name: 'Operators' })).toBeVisible();
});

test('Modules page loads', async ({ page }) => {
  await page.goto('/modules');
  await expect(page.getByRole('heading', { name: 'Modules' })).toBeVisible();
  await expect(page.getByText('Refresh')).toBeVisible();
  // Check info banner
  await expect(page.getByText('Dynamic modules extend implant capabilities')).toBeVisible();
});

test('Reports page loads', async ({ page }) => {
  await page.goto('/reports');
  // Wait for the heading to appear
  await expect(page.locator('h1:has-text("Reports")')).toBeVisible({ timeout: 10000 });
  await expect(page.locator('button:has-text("Generate Report")')).toBeVisible();
});

test.describe('Loot Page Features', () => {
  test('filter buttons work', async ({ page }) => {
    await page.goto('/loot');

    // Wait for page to load - use getByRole for h1
    await expect(page.getByRole('heading', { name: 'Loot', level: 1 })).toBeVisible({ timeout: 10000 });

    // Check filter buttons exist (use exact match for "All" to avoid matching "Export All")
    await expect(page.getByRole('button', { name: 'All', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Credentials' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Files' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Tokens' })).toBeVisible();

    // Click filter and verify it works
    await page.getByRole('button', { name: 'Credentials' }).click();
    await page.getByRole('button', { name: 'All', exact: true }).click();
  });

  test('search input works', async ({ page }) => {
    await page.goto('/loot');

    const searchInput = page.getByPlaceholder('Search loot...');
    await expect(searchInput).toBeVisible();

    // Type in search
    await searchInput.fill('admin');
    // Should trigger search (debounced)
    await page.waitForTimeout(500);
  });

  test('export button is clickable', async ({ page }) => {
    await page.goto('/loot');

    const exportBtn = page.getByRole('button', { name: 'Export All' });
    await expect(exportBtn).toBeVisible();
    await expect(exportBtn).toBeEnabled();
  });
});

test.describe('Listeners Page Features', () => {
  test('create listener modal opens', async ({ page }) => {
    await page.goto('/listeners');

    // Click create button
    await page.getByRole('button', { name: 'Create Listener' }).click();

    // Modal should open
    await expect(page.getByRole('heading', { name: 'Create Listener' })).toBeVisible();

    // Check form fields exist
    await expect(page.getByLabel('Protocol')).toBeVisible();
    await expect(page.getByLabel(/Bind Address/i)).toBeVisible();
    await expect(page.getByLabel(/Port/i)).toBeVisible();

    // Cancel button should close modal
    await page.getByRole('button', { name: 'Cancel' }).click();
    await expect(page.getByRole('heading', { name: 'Create Listener' })).not.toBeVisible();
  });
});

test.describe('Operators Page Features', () => {
  test('add operator modal opens', async ({ page }) => {
    await page.goto('/operators');

    // Wait for page to load
    await expect(page.locator('h1:has-text("Operators")')).toBeVisible({ timeout: 10000 });

    // Click add button
    await page.locator('button:has-text("Add Operator")').first().click();

    // Modal should open - title is "Add Operator"
    await expect(page.locator('h2:has-text("Add Operator")')).toBeVisible({ timeout: 5000 });

    // Check form fields exist (Username input)
    await expect(page.locator('input[placeholder="operator-name"]')).toBeVisible();

    // Close button should work (use aria-label for SVG close button)
    await page.locator('button[aria-label="Close modal"]').click();
    await expect(page.locator('h2:has-text("Add Operator")')).not.toBeVisible();
  });
});

test.describe('Navigation', () => {
  test('sidebar navigation works', async ({ page }) => {
    await page.goto('/');

    // Check all nav links exist and work
    const navLinks = [
      { name: 'Dashboard', url: '/dashboard' },
      { name: 'Sessions', url: '/sessions' },
      { name: 'Listeners', url: '/listeners' },
      { name: 'Loot', url: '/loot' },
      { name: 'Modules', url: '/modules' },
      { name: 'Reports', url: '/reports' },
      { name: 'Operators', url: '/operators' },
    ];

    for (const link of navLinks) {
      const navLink = page.locator(`nav a:has-text("${link.name}")`);
      await expect(navLink).toBeVisible();
    }

    // Click Modules and verify navigation
    await page.locator('nav a:has-text("Modules")').click();
    await expect(page).toHaveURL(/\/modules/);
    await expect(page.getByRole('heading', { name: 'Modules' })).toBeVisible();
  });
});
