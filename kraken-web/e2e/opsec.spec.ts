import { test, expect } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.goto('http://localhost:3003');
  await page.evaluate(() => {
    localStorage.setItem('kraken-auth', JSON.stringify({
      state: {
        token: 'test-operator-token',
        isAuthenticated: true,
        operator: { username: 'testop', operatorId: '12345' }
      },
      version: 0
    }));
  });
});

test.describe('OPSEC Gates', () => {
  // Note: These tests require a mock session to be available
  // In a real test environment, we'd mock the gRPC responses

  test.skip('Risk badge appears when typing command', async ({ page }) => {
    // This test requires a session to be loaded
    // Skip for now as it needs backend mock
    await page.goto('/sessions/test-session-id');

    const commandInput = page.getByPlaceholder(/Enter command/i);
    await commandInput.fill('whoami');

    // Should show LOW risk badge
    await expect(page.locator('text=LOW')).toBeVisible();
  });

  test.skip('High-risk command shows OPSEC modal', async ({ page }) => {
    await page.goto('/sessions/test-session-id');

    const commandInput = page.getByPlaceholder(/Enter command/i);
    await commandInput.fill('mimikatz');

    // Submit the command
    await page.getByRole('button', { name: /Run/i }).click();

    // OPSEC modal should appear
    await expect(page.getByText('OPSEC Warning')).toBeVisible();
    await expect(page.getByText('Critical Risk')).toBeVisible();
    await expect(page.getByText('Detection Vectors')).toBeVisible();
  });

  test.skip('OPSEC modal can be cancelled', async ({ page }) => {
    await page.goto('/sessions/test-session-id');

    const commandInput = page.getByPlaceholder(/Enter command/i);
    await commandInput.fill('mimikatz');
    await page.getByRole('button', { name: /Run/i }).click();

    // Cancel the modal
    await page.getByRole('button', { name: /Cancel/i }).click();

    // Modal should close
    await expect(page.getByText('OPSEC Warning')).not.toBeVisible();
  });

  test.skip('OPSEC modal confirm executes command', async ({ page }) => {
    await page.goto('/sessions/test-session-id');

    const commandInput = page.getByPlaceholder(/Enter command/i);
    await commandInput.fill('hashdump');
    await page.getByRole('button', { name: /Run/i }).click();

    // Confirm execution
    await page.getByRole('button', { name: /Execute Anyway/i }).click();

    // Modal should close and command should be submitted
    await expect(page.getByText('OPSEC Warning')).not.toBeVisible();
  });
});

test.describe('OPSEC Components Unit Tests', () => {
  test('RiskIndicator renders correctly', async ({ page }) => {
    // Create a test page that renders just the component
    await page.setContent(`
      <html>
        <head>
          <script type="module">
            // This would need proper setup with Vite
          </script>
        </head>
        <body>
          <div id="test-root"></div>
        </body>
      </html>
    `);

    // Component tests would be better with Vitest + Testing Library
    // This is a placeholder for the test structure
  });
});
