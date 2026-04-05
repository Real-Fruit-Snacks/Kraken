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

test.describe('Collaboration Panel', () => {
  test('Collab panel toggle button exists', async ({ page }) => {
    await page.goto('/dashboard');

    // Find the toggle button on the right edge
    const toggleButton = page.locator('button[title*="collaboration"]');
    await expect(toggleButton).toBeVisible();
  });

  test('Collab panel opens when toggle clicked', async ({ page }) => {
    await page.goto('/dashboard');

    // Click the toggle button
    const toggleButton = page.locator('button[title*="collaboration"]');
    await toggleButton.click();

    // Panel should be visible with tabs - use text matching to find tab buttons
    // The collab panel tabs are in an aside element on the right
    const collabPanel = page.locator('aside').filter({ has: page.getByText('Event Feed') });
    await expect(collabPanel).toBeVisible();
    await expect(page.getByText('Event Feed')).toBeVisible();
  });

  test('Collab panel closes when toggle clicked again', async ({ page }) => {
    await page.goto('/dashboard');

    const toggleButton = page.locator('button[title*="collaboration"]');

    // Open
    await toggleButton.click();
    await expect(page.getByRole('button', { name: /Events/i })).toBeVisible();

    // Close
    await toggleButton.click();

    // Wait for animation
    await page.waitForTimeout(400);

    // Panel content should not be visible (panel width is 0)
    await expect(page.getByRole('button', { name: /Events/i })).not.toBeVisible();
  });

  test('Events tab shows event feed', async ({ page }) => {
    await page.goto('/dashboard');

    const toggleButton = page.locator('button[title*="collaboration"]');
    await toggleButton.click();

    // Events tab should be active by default
    await expect(page.getByText('Event Feed')).toBeVisible();
    await expect(page.getByText('Auto-scroll')).toBeVisible();
  });

  test('Chat tab shows chat interface', async ({ page }) => {
    await page.goto('/dashboard');

    const toggleButton = page.locator('button[title*="collaboration"]');
    await toggleButton.click();

    // Click Chat tab (exact match to avoid filter button)
    await page.getByRole('button', { name: 'Chat', exact: true }).click();

    // Should show chat UI (may show unavailable without backend)
    const chatHeading = page.getByText('Operator Chat');
    const unavailable = page.getByText('Chat unavailable');

    // Either chat is available or shows unavailable message
    await expect(chatHeading.or(unavailable)).toBeVisible();
  });

  test('Team tab shows operator list', async ({ page }) => {
    await page.goto('/dashboard');

    const toggleButton = page.locator('button[title*="collaboration"]');
    await toggleButton.click();

    // Click Team tab
    await page.getByRole('button', { name: /Team/i }).click();

    // Should show operators heading or empty state
    const heading = page.getByText('Online Operators');
    const empty = page.getByText('No operators online');

    await expect(heading.or(empty)).toBeVisible();
  });

  test('Event filters exist', async ({ page }) => {
    await page.goto('/dashboard');

    const toggleButton = page.locator('button[title*="collaboration"]');
    await toggleButton.click();

    // Check filter buttons
    await expect(page.getByRole('button', { name: /All/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /Operators/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /Sessions/i })).toBeVisible();
  });
});
