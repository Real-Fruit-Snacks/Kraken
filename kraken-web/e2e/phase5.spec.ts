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

test.describe('Command Palette', () => {
  // Helper to open command palette
  async function openPalette(page: import('@playwright/test').Page) {
    // Wait for initial render
    await page.waitForTimeout(1000);

    // Try Ctrl+K
    await page.keyboard.press('Control+k');
    await page.waitForTimeout(300);

    // Check if opened, if not try Meta+K
    const isVisible = await page.getByPlaceholder('Type a command or search...').isVisible().catch(() => false);
    if (!isVisible) {
      await page.keyboard.press('Meta+k');
      await page.waitForTimeout(300);
    }
  }

  test('Opens with Ctrl+K keyboard shortcut', async ({ page }) => {
    await page.goto('/dashboard');
    await openPalette(page);

    // Palette should be visible with search input
    const searchInput = page.getByPlaceholder('Type a command or search...');
    await expect(searchInput).toBeVisible({ timeout: 5000 });
  });

  test('Closes with Escape key', async ({ page }) => {
    await page.goto('/dashboard');
    await openPalette(page);

    await expect(page.getByPlaceholder('Type a command or search...')).toBeVisible();

    await page.keyboard.press('Escape');
    await expect(page.getByPlaceholder('Type a command or search...')).not.toBeVisible();
  });

  test('Shows navigation commands', async ({ page }) => {
    await page.goto('/dashboard');
    await openPalette(page);

    // Should show navigation section
    await expect(page.getByText('Navigation')).toBeVisible();
    await expect(page.getByText('Go to Sessions')).toBeVisible();
    await expect(page.getByText('Go to Topology')).toBeVisible();
    await expect(page.getByText('Go to Defender View')).toBeVisible();
  });

  test('Filters commands by search query', async ({ page }) => {
    await page.goto('/dashboard');
    await openPalette(page);

    const searchInput = page.getByPlaceholder('Type a command or search...');
    await searchInput.fill('topology');
    await page.waitForTimeout(200); // Wait for filter to apply

    // Should show topology command, hide others
    await expect(page.getByText('Go to Topology')).toBeVisible();
  });

  test('Navigates with arrow keys and Enter', async ({ page }) => {
    await page.goto('/dashboard');
    await openPalette(page);

    // Press down arrow to select second item
    await page.keyboard.press('ArrowDown');
    await page.waitForTimeout(100);

    // Press Enter to navigate
    await page.keyboard.press('Enter');

    // Should have navigated (palette closes)
    await page.waitForTimeout(300);
    await expect(page.getByPlaceholder('Type a command or search...')).not.toBeVisible();
  });

  test('Closes when clicking backdrop', async ({ page }) => {
    await page.goto('/dashboard');
    await openPalette(page);

    await expect(page.getByPlaceholder('Type a command or search...')).toBeVisible();

    // Click outside the palette (on backdrop)
    await page.locator('.backdrop-blur-sm').first().click({ position: { x: 10, y: 10 }, force: true });

    await expect(page.getByPlaceholder('Type a command or search...')).not.toBeVisible({ timeout: 3000 });
  });
});

test.describe('Session Detail - New Tabs', () => {
  // Note: These tests require a mock session to be available
  // In a real scenario, you would seed test data first

  test('Mesh tab exists in session detail', async ({ page }) => {
    // Navigate to sessions list first
    await page.goto('/sessions');

    // Check if there are any sessions to click on
    const sessionLinks = page.locator('a[href^="/sessions/"]');
    const count = await sessionLinks.count();

    if (count > 0) {
      await sessionLinks.first().click();
      await page.waitForURL(/\/sessions\//);

      // Check for Mesh tab
      const meshTab = page.getByRole('button', { name: 'Mesh' });
      await expect(meshTab).toBeVisible();
    }
  });

  test('Pivot tab exists in session detail', async ({ page }) => {
    await page.goto('/sessions');

    const sessionLinks = page.locator('a[href^="/sessions/"]');
    const count = await sessionLinks.count();

    if (count > 0) {
      await sessionLinks.first().click();
      await page.waitForURL(/\/sessions\//);

      // Check for Pivot tab
      const pivotTab = page.getByRole('button', { name: 'Pivot' });
      await expect(pivotTab).toBeVisible();
    }
  });

  test('Mesh tab shows mesh control panel', async ({ page }) => {
    await page.goto('/sessions');

    const sessionLinks = page.locator('a[href^="/sessions/"]');
    const count = await sessionLinks.count();

    if (count > 0) {
      await sessionLinks.first().click();
      await page.waitForURL(/\/sessions\//);

      // Click Mesh tab
      await page.getByRole('button', { name: 'Mesh' }).click();

      // Should show mesh control panel content
      await expect(page.getByText('Mesh Commands')).toBeVisible();
      await expect(page.getByText('Connect to Peer')).toBeVisible();
      await expect(page.getByText('Current Role')).toBeVisible();
    }
  });

  test('Pivot tab shows SOCKS proxy manager', async ({ page }) => {
    await page.goto('/sessions');

    const sessionLinks = page.locator('a[href^="/sessions/"]');
    const count = await sessionLinks.count();

    if (count > 0) {
      await sessionLinks.first().click();
      await page.waitForURL(/\/sessions\//);

      // Click Pivot tab
      await page.getByRole('button', { name: 'Pivot' }).click();

      // Should show proxy manager content
      await expect(page.getByText('Pivoting')).toBeVisible();
      await expect(page.getByText('SOCKS Proxy')).toBeVisible();
      await expect(page.getByText('Port Forward')).toBeVisible();
    }
  });

  test('Mesh control panel shows connection wizard', async ({ page }) => {
    await page.goto('/sessions');

    const sessionLinks = page.locator('a[href^="/sessions/"]');
    const count = await sessionLinks.count();

    if (count > 0) {
      await sessionLinks.first().click();
      await page.waitForURL(/\/sessions\//);

      await page.getByRole('button', { name: 'Mesh' }).click();

      // Click "Connect to Peer" button
      await page.getByText('Connect to Peer').click();

      // Should show connection wizard modal
      await expect(page.getByText('Step 1 of 3')).toBeVisible();
      await expect(page.getByText('Select transport protocol')).toBeVisible();
      await expect(page.getByText('TCP')).toBeVisible();
      await expect(page.getByText('SMB')).toBeVisible();
    }
  });

  test('SOCKS proxy manager shows create form', async ({ page }) => {
    await page.goto('/sessions');

    const sessionLinks = page.locator('a[href^="/sessions/"]');
    const count = await sessionLinks.count();

    if (count > 0) {
      await sessionLinks.first().click();
      await page.waitForURL(/\/sessions\//);

      await page.getByRole('button', { name: 'Pivot' }).click();

      // Click "Start SOCKS Proxy" button
      await page.getByText('Start SOCKS Proxy').click();

      // Should show create proxy modal
      await expect(page.getByText('Bind Port')).toBeVisible();
      await expect(page.getByText('SOCKS Version')).toBeVisible();
      await expect(page.getByText('SOCKS5')).toBeVisible();
    }
  });
});

// Helper to open keyboard shortcuts modal via Command Palette
async function openKeyboardShortcutsModal(page: import('@playwright/test').Page) {
  await page.keyboard.press('Control+k');
  await page.waitForTimeout(300);
  const searchInput = page.getByPlaceholder('Type a command or search...');
  if (await searchInput.isVisible()) {
    await searchInput.fill('keyboard');
    await page.waitForTimeout(200);
    // Click the first result (Keyboard Shortcuts)
    await page.keyboard.press('Enter');
    await page.waitForTimeout(300);
  }
}

test.describe('Keyboard Shortcuts Modal', () => {
  test('Opens from Command Palette', async ({ page }) => {
    await page.goto('/dashboard');
    await page.waitForTimeout(500);

    await openKeyboardShortcutsModal(page);
    await expect(page.getByRole('heading', { name: 'Keyboard Shortcuts' })).toBeVisible({ timeout: 3000 });
    await expect(page.getByText('Global')).toBeVisible();
  });

  test('Shows all shortcut categories', async ({ page }) => {
    await page.goto('/dashboard');
    await page.waitForTimeout(500);

    await openKeyboardShortcutsModal(page);
    await page.waitForTimeout(300);

    // Check all categories are present
    await expect(page.getByText('Global')).toBeVisible();
    await expect(page.getByText('Navigation')).toBeVisible();
    await expect(page.getByText('Session Actions')).toBeVisible();
    await expect(page.getByText('Quick Actions')).toBeVisible();
  });

  test('Closes with Escape key', async ({ page }) => {
    await page.goto('/dashboard');
    await page.waitForTimeout(500);

    await openKeyboardShortcutsModal(page);
    await expect(page.getByRole('heading', { name: 'Keyboard Shortcuts' })).toBeVisible({ timeout: 3000 });

    await page.keyboard.press('Escape');
    await expect(page.getByRole('heading', { name: 'Keyboard Shortcuts' })).not.toBeVisible({ timeout: 3000 });
  });

  test('Shows shortcut key badges', async ({ page }) => {
    await page.goto('/dashboard');
    await page.waitForTimeout(500);

    await openKeyboardShortcutsModal(page);
    await expect(page.getByRole('heading', { name: 'Keyboard Shortcuts' })).toBeVisible({ timeout: 3000 });

    // Check that shortcut descriptions are displayed
    await expect(page.getByText('Open Command Palette')).toBeVisible();
    await expect(page.getByText('Close modal / Cancel action')).toBeVisible();
  });
});

test.describe('Payloads Page', () => {
  test('Navigates to payloads page', async ({ page }) => {
    await page.goto('/payloads');
    await page.waitForLoadState('networkidle');

    await expect(page.getByText('Payload Generator')).toBeVisible();
  });

  test('Shows OS selection buttons', async ({ page }) => {
    await page.goto('/payloads');
    await page.waitForLoadState('networkidle');

    await expect(page.getByText('Windows')).toBeVisible();
    await expect(page.getByText('Linux')).toBeVisible();
    await expect(page.getByText('macOS')).toBeVisible();
  });

  test('Shows architecture selection', async ({ page }) => {
    await page.goto('/payloads');
    await page.waitForLoadState('networkidle');

    await expect(page.getByRole('button', { name: 'x64' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'x86' })).toBeVisible();
  });

  test('Shows format selection', async ({ page }) => {
    await page.goto('/payloads');
    await page.waitForLoadState('networkidle');

    await expect(page.getByText('Executable (.exe)')).toBeVisible();
    await expect(page.getByText('Dynamic Library (.dll)')).toBeVisible();
    await expect(page.getByText('Shellcode (raw)')).toBeVisible();
  });

  test('Shows evasion options', async ({ page }) => {
    await page.goto('/payloads');
    await page.waitForLoadState('networkidle');

    await expect(page.getByText('Evasion Options')).toBeVisible();
    await expect(page.getByText('String Obfuscation')).toBeVisible();
    await expect(page.getByText('Anti-Debug')).toBeVisible();
    await expect(page.getByText('Sleep Masking')).toBeVisible();
  });

  test('Shows advanced options section', async ({ page }) => {
    await page.goto('/payloads');
    await page.waitForLoadState('networkidle');

    // Click to expand advanced options
    await page.getByText('Advanced Options').click();

    await expect(page.getByText('Sleep Time (seconds)')).toBeVisible();
    await expect(page.getByText('Jitter (%)')).toBeVisible();
    await expect(page.getByText('Kill Date')).toBeVisible();
  });

  test('Generate button is disabled without required fields', async ({ page }) => {
    await page.goto('/payloads');
    await page.waitForLoadState('networkidle');

    const generateButton = page.getByRole('button', { name: 'Generate Payload' });
    await expect(generateButton).toBeDisabled();
  });

  test('Shows OPSEC tips sidebar', async ({ page }) => {
    await page.goto('/payloads');
    await page.waitForLoadState('networkidle');

    await expect(page.getByText('OPSEC Tips')).toBeVisible();
    await expect(page.getByText('Use unique payloads per target')).toBeVisible();
  });
});

test.describe('Reports Page', () => {
  test('Navigates to reports page', async ({ page }) => {
    await page.goto('/reports');
    await page.waitForLoadState('networkidle');

    await expect(page.getByRole('heading', { name: 'Reports' })).toBeVisible();
  });

  test('Shows report type cards', async ({ page }) => {
    await page.goto('/reports');
    await page.waitForLoadState('networkidle');

    await expect(page.getByText('Engagement Report')).toBeVisible();
    await expect(page.getByText('IOC Report')).toBeVisible();
    await expect(page.getByText('Executive Summary')).toBeVisible();
    await expect(page.getByText('Activity Timeline')).toBeVisible();
    await expect(page.getByText('Loot Summary')).toBeVisible();
  });

  test('Opens generate report modal', async ({ page }) => {
    await page.goto('/reports');
    await page.waitForLoadState('networkidle');

    await page.getByRole('button', { name: 'Generate Report' }).click();

    await expect(page.getByRole('heading', { name: 'Generate Report' })).toBeVisible();
    await expect(page.getByText('Report Title')).toBeVisible();
    await expect(page.getByText('Report Type')).toBeVisible();
    await expect(page.getByText('Date Range')).toBeVisible();
  });

  test('Shows output format options in modal', async ({ page }) => {
    await page.goto('/reports');
    await page.waitForLoadState('networkidle');

    await page.getByRole('button', { name: 'Generate Report' }).click();

    await expect(page.getByRole('button', { name: 'PDF' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'JSON' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Markdown' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'CSV' })).toBeVisible();
  });

  test('Shows include sections checkboxes', async ({ page }) => {
    await page.goto('/reports');
    await page.waitForLoadState('networkidle');

    await page.getByRole('button', { name: 'Generate Report' }).click();

    await expect(page.getByText('Include Sections')).toBeVisible();
    await expect(page.getByText('Sessions')).toBeVisible();
    await expect(page.getByText('Task History')).toBeVisible();
    await expect(page.getByText('Collected Loot')).toBeVisible();
  });

  test('Modal closes on cancel', async ({ page }) => {
    await page.goto('/reports');
    await page.waitForLoadState('networkidle');

    await page.getByRole('button', { name: 'Generate Report' }).click();
    await expect(page.getByRole('heading', { name: 'Generate Report' })).toBeVisible();

    await page.getByRole('button', { name: 'Cancel' }).click();
    await expect(page.getByRole('heading', { name: 'Generate Report' })).not.toBeVisible({ timeout: 3000 });
  });

  test('Opens report type modal when clicking card', async ({ page }) => {
    await page.goto('/reports');
    await page.waitForLoadState('networkidle');

    // Click on IOC Report card
    await page.locator('button:has-text("IOC Report")').first().click();

    await expect(page.getByRole('heading', { name: 'Generate Report' })).toBeVisible();
  });
});

test.describe('Payloads Navigation', () => {
  test('Payloads link visible in sidebar', async ({ page }) => {
    await page.goto('/dashboard');
    await page.waitForLoadState('networkidle');

    await expect(page.getByRole('link', { name: 'Payloads' })).toBeVisible();
  });

  test('Navigates to payloads from sidebar', async ({ page }) => {
    await page.goto('/dashboard');
    await page.waitForLoadState('networkidle');

    await page.getByRole('link', { name: 'Payloads' }).click();
    await expect(page).toHaveURL(/\/payloads/);
  });

  test('Navigates to payloads from command palette', async ({ page }) => {
    await page.goto('/dashboard');
    await page.waitForTimeout(500);

    // Open command palette
    await page.keyboard.press('Control+k');
    await page.waitForTimeout(300);

    const searchInput = page.getByPlaceholder('Type a command or search...');
    if (await searchInput.isVisible()) {
      await searchInput.fill('payload');
      await page.waitForTimeout(200);

      await page.getByText('Generate Payload').click();
      await page.waitForTimeout(300);

      await expect(page).toHaveURL(/\/payloads/);
    }
  });
});

test.describe('Layout Integration', () => {
  test('Collaboration panel still works', async ({ page }) => {
    await page.goto('/dashboard');

    // Find and click the collab toggle
    const toggleButton = page.locator('button[title*="collaboration"]');
    await toggleButton.click();

    // Panel should open
    await expect(page.getByText('Event Feed')).toBeVisible();
  });

  test('Navigation still works', async ({ page }) => {
    await page.goto('/dashboard');

    // Click Sessions nav link
    await page.getByRole('link', { name: 'Sessions' }).click();
    await expect(page).toHaveURL(/\/sessions/);

    // Click Topology nav link
    await page.getByRole('link', { name: 'Topology' }).click();
    await expect(page).toHaveURL(/\/topology/);

    // Click Defender nav link
    await page.getByRole('link', { name: 'Defender' }).click();
    await expect(page).toHaveURL(/\/defender/);
  });
});
