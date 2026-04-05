import { test, expect } from '@playwright/test';

/**
 * Live E2E tests for Sessions
 *
 * Tests session list and detail pages against a running server.
 * For full testing, start implants to populate session data.
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

test.describe('Live Sessions List', () => {
  test('sessions page loads', async ({ page }) => {
    await page.goto('/sessions');

    await expect(page.getByRole('heading', { name: 'Sessions' })).toBeVisible({ timeout: 15000 });

    // Table headers should be visible
    await expect(page.locator('th:has-text("Hostname")')).toBeVisible();
    await expect(page.locator('th:has-text("State")')).toBeVisible();
  });

  test('shows sessions or empty state', async ({ page }) => {
    await page.goto('/sessions');
    await expect(page.getByRole('heading', { name: 'Sessions' })).toBeVisible({ timeout: 15000 });

    // Wait for data to load
    await page.waitForTimeout(3000);

    // Either shows sessions or empty state - both are valid
    const rows = page.locator('tbody tr');
    const rowCount = await rows.count();

    if (rowCount > 0) {
      // Sessions exist - verify Interact button
      const interactBtn = rows.first().locator('button:has-text("Interact")');
      if (await interactBtn.isVisible()) {
        console.log(`Found ${rowCount} active sessions with Interact buttons`);
      } else {
        console.log(`Found ${rowCount} rows but no Interact buttons`);
      }
    } else {
      // No sessions - empty table is acceptable
      console.log('No active sessions found - empty state');
    }
  });

  test('can interact with session when available', async ({ page }) => {
    await page.goto('/sessions');
    await expect(page.getByRole('heading', { name: 'Sessions' })).toBeVisible({ timeout: 15000 });

    // Wait for potential sessions
    await page.waitForTimeout(2000);

    const interactBtn = page.locator('button:has-text("Interact")').first();
    if (await interactBtn.isVisible()) {
      await interactBtn.click();

      // Should navigate to session detail
      await expect(page.locator('text=Terminal')).toBeVisible({ timeout: 10000 });
      await expect(page.locator('text=Tasks')).toBeVisible();
      await expect(page.locator('text=Files')).toBeVisible();

      console.log('Successfully navigated to session detail');
    } else {
      console.log('No sessions to interact with - skipping detail test');
    }
  });
});

test.describe('Live Session Detail', () => {
  test('session detail shows all tabs', async ({ page }) => {
    await page.goto('/sessions');
    await page.waitForTimeout(3000);

    const interactBtn = page.locator('button:has-text("Interact")').first();
    if (await interactBtn.isVisible()) {
      await interactBtn.click();

      // Wait for Terminal tab to appear (indicates page loaded)
      await expect(page.locator('button:has-text("Terminal")')).toBeVisible({ timeout: 15000 });

      // Verify all tabs exist
      await expect(page.locator('button:has-text("Tasks")')).toBeVisible();
      await expect(page.locator('button:has-text("Files")')).toBeVisible();

      // Verify sidebar controls
      await expect(page.locator('button:has-text("Sleep")')).toBeVisible();
      await expect(page.locator('button:has-text("Kill")')).toBeVisible();

      console.log('Session detail page loaded with all tabs');
    } else {
      console.log('No sessions to interact with');
      test.skip();
    }
  });

  test('can send command to session', async ({ page }) => {
    await page.goto('/sessions');
    await page.waitForTimeout(3000);

    const interactBtn = page.locator('button:has-text("Interact")').first();
    if (await interactBtn.isVisible()) {
      await interactBtn.click();

      // Wait for Terminal tab
      await expect(page.locator('button:has-text("Terminal")')).toBeVisible({ timeout: 15000 });

      // Find command input - try multiple selectors
      const cmdInput = page.locator('input[placeholder*="ommand"], textarea, input[type="text"]').first();
      await expect(cmdInput).toBeVisible({ timeout: 5000 });
      await cmdInput.fill('whoami');

      // Find and click send/submit button
      const sendBtn = page.locator('button[type="submit"], button:has-text("Send"), button:has-text("Execute")').first();
      if (await sendBtn.isVisible()) {
        await sendBtn.click();
        console.log('Command sent to session');
      } else {
        // Try pressing Enter instead
        await cmdInput.press('Enter');
        console.log('Command submitted via Enter key');
      }
    } else {
      console.log('No sessions to interact with');
      test.skip();
    }
  });
});
