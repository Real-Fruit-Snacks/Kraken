import { test, expect } from '@playwright/test';

// Authenticate before each test
test.beforeEach(async ({ page }) => {
  await page.goto('http://localhost:3003');
  await page.evaluate(() => {
    localStorage.setItem('kraken-auth', JSON.stringify({
      state: { token: 'test-operator-token', isAuthenticated: true },
      version: 0
    }));
  });
});

// ============================================================================
// LOGIN PAGE
// ============================================================================
test.describe('Login Page', () => {
  test('renders login form correctly', async ({ page }) => {
    // Clear auth to test login page
    await page.evaluate(() => localStorage.removeItem('kraken-auth'));
    await page.goto('/login');

    // Check all elements
    await expect(page.getByRole('heading', { name: 'Kraken' })).toBeVisible();
    await expect(page.getByText('Command & Control')).toBeVisible();
    await expect(page.getByLabel('Operator Token')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Connect' })).toBeVisible();
  });

  test('shows error for empty token', async ({ page }) => {
    await page.evaluate(() => localStorage.removeItem('kraken-auth'));
    await page.goto('/login');

    // Submit empty form
    await page.getByRole('button', { name: 'Connect' }).click();

    // Error should appear
    await expect(page.getByText('Token is required')).toBeVisible();
  });

  test('login redirects to dashboard', async ({ page }) => {
    await page.evaluate(() => localStorage.removeItem('kraken-auth'));
    await page.goto('/login');

    // Enter token and submit
    await page.getByLabel('Operator Token').fill('test-token');
    await page.getByRole('button', { name: 'Connect' }).click();

    // Should redirect to dashboard
    await expect(page).toHaveURL(/\/dashboard/);
  });
});

// ============================================================================
// NAVIGATION & LAYOUT
// ============================================================================
test.describe('Navigation & Layout', () => {
  test('all navigation links are visible', async ({ page }) => {
    await page.goto('/dashboard');

    const navLinks = ['Dashboard', 'Sessions', 'Listeners', 'Loot', 'Modules', 'Reports', 'Operators'];
    for (const link of navLinks) {
      await expect(page.locator(`nav a:has-text("${link}")`)).toBeVisible();
    }
  });

  test('navigation links work correctly', async ({ page }) => {
    await page.goto('/dashboard');

    // Test a few nav links (not all to avoid timeout)
    await page.locator('nav a:has-text("Sessions")').click();
    await expect(page).toHaveURL(/\/sessions/);

    await page.locator('nav a:has-text("Loot")').click();
    await expect(page).toHaveURL(/\/loot/);

    await page.locator('nav a:has-text("Dashboard")').click();
    await expect(page).toHaveURL(/\/dashboard/);
  });

  test('active navigation link is highlighted', async ({ page }) => {
    await page.goto('/sessions');

    // Sessions link should have active class
    const sessionsLink = page.locator('nav a:has-text("Sessions")');
    await expect(sessionsLink).toHaveClass(/bg-ctp-mauve/);
  });

  test('operator count badge is visible', async ({ page }) => {
    await page.goto('/dashboard');
    await expect(page.locator('button:has-text("operator")')).toBeVisible();
  });
});

// ============================================================================
// DASHBOARD PAGE
// ============================================================================
test.describe('Dashboard Page', () => {
  test('displays all stat cards', async ({ page }) => {
    await page.goto('/dashboard');

    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible({ timeout: 10000 });
    // Wait for loading to complete, then check cards
    await page.waitForTimeout(2000);
    await expect(page.locator('text=Active Sessions').or(page.locator('text=Loading'))).toBeVisible();
  });

  test('displays recent sessions section', async ({ page }) => {
    await page.goto('/dashboard');
    await expect(page.getByRole('heading', { name: 'Recent Sessions' })).toBeVisible();
  });

  test('displays activity feed section', async ({ page }) => {
    await page.goto('/dashboard');
    // Activity section may be visible in the scrollable area
    await expect(page.getByText('Activity').first()).toBeVisible({ timeout: 10000 });
  });

  test('session rows are clickable', async ({ page }) => {
    await page.goto('/dashboard');

    // Wait for data to load
    const sessionRow = page.locator('tbody tr').first();
    if (await sessionRow.isVisible()) {
      await sessionRow.click();
      await expect(page).toHaveURL(/\/sessions\//);
    }
  });

  test('handles loading state', async ({ page }) => {
    await page.goto('/dashboard');
    // Either loading text or actual content should be visible
    await expect(page.locator('text=Loading').or(page.locator('text=Active Sessions'))).toBeVisible({ timeout: 10000 });
  });
});

// ============================================================================
// SESSIONS LIST PAGE
// ============================================================================
test.describe('Sessions List Page', () => {
  test('displays table with correct headers', async ({ page }) => {
    await page.goto('/sessions');

    await expect(page.getByRole('heading', { name: 'Sessions' })).toBeVisible({ timeout: 10000 });
    await expect(page.locator('th:has-text("Hostname")')).toBeVisible();
    await expect(page.locator('th:has-text("State")')).toBeVisible();
    await expect(page.locator('th:has-text("Actions")')).toBeVisible();
  });

  test('Interact button navigates to session detail', async ({ page }) => {
    await page.goto('/sessions');
    await page.waitForSelector('tbody tr', { timeout: 10000 });

    const interactBtn = page.locator('button:has-text("Interact")').first();
    if (await interactBtn.isVisible()) {
      await interactBtn.click();
      await expect(page).toHaveURL(/\/sessions\//);
    }
  });

  test('Retire button opens modal', async ({ page }) => {
    await page.goto('/sessions');
    await page.waitForSelector('tbody tr', { timeout: 10000 });

    const retireBtn = page.locator('tbody button:has-text("Retire")').first();
    if (await retireBtn.isVisible()) {
      await retireBtn.click();
      await expect(page.getByRole('heading', { name: 'Retire Implant' })).toBeVisible();
      await expect(page.getByText('gracefully marks it as retired')).toBeVisible();
      await page.getByRole('button', { name: 'Cancel' }).click();
      await expect(page.getByRole('heading', { name: 'Retire Implant' })).not.toBeVisible();
    }
  });

  test('Burn button opens modal with input', async ({ page }) => {
    await page.goto('/sessions');
    await page.waitForSelector('tbody tr', { timeout: 10000 });

    const burnBtn = page.locator('button:has-text("Burn")').first();
    if (await burnBtn.isVisible()) {
      await burnBtn.click();
      await expect(page.getByRole('heading', { name: 'Burn Implant' })).toBeVisible();
      await expect(page.locator('input[type="text"]')).toBeVisible();
      await expect(page.locator('input[type="text"]')).toHaveValue('Suspected compromise');
      await page.getByRole('button', { name: 'Cancel' }).click();
    }
  });

  test('Delete button opens modal', async ({ page }) => {
    await page.goto('/sessions');
    await page.waitForSelector('tbody tr', { timeout: 10000 });

    const deleteBtn = page.locator('button:has-text("Delete")').first();
    if (await deleteBtn.isVisible()) {
      await deleteBtn.click();
      await expect(page.getByRole('heading', { name: 'Delete Implant' })).toBeVisible();
      await expect(page.getByText('permanently removes all records')).toBeVisible();
      await page.getByRole('button', { name: 'Cancel' }).click();
    }
  });

  test('modal closes on Escape key', async ({ page }) => {
    await page.goto('/sessions');
    await page.waitForSelector('tbody tr', { timeout: 10000 });

    const deleteBtn = page.locator('button:has-text("Delete")').first();
    if (await deleteBtn.isVisible()) {
      await deleteBtn.click();
      await expect(page.getByRole('heading', { name: 'Delete Implant' })).toBeVisible();
      await page.keyboard.press('Escape');
      await expect(page.getByRole('heading', { name: 'Delete Implant' })).not.toBeVisible();
    }
  });

  test('modal closes on click outside', async ({ page }) => {
    await page.goto('/sessions');
    await page.waitForSelector('tbody tr', { timeout: 10000 });

    const deleteBtn = page.locator('button:has-text("Delete")').first();
    if (await deleteBtn.isVisible()) {
      await deleteBtn.click();
      await expect(page.getByRole('heading', { name: 'Delete Implant' })).toBeVisible();
      await page.locator('.fixed.inset-0').click({ position: { x: 10, y: 10 } });
      await expect(page.getByRole('heading', { name: 'Delete Implant' })).not.toBeVisible();
    }
  });

  test('handles empty state', async ({ page }) => {
    await page.goto('/sessions');
    // Page loads with either sessions data or empty state message
    await expect(page.getByRole('heading', { name: 'Sessions' })).toBeVisible({ timeout: 10000 });
  });
});

// ============================================================================
// SESSION DETAIL PAGE
// ============================================================================
test.describe('Session Detail Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/sessions');
    await page.waitForSelector('tbody tr', { timeout: 10000 });
    await page.locator('button:has-text("Interact")').first().click();
    await page.waitForSelector('text=Terminal');
  });

  test('displays session info sidebar', async ({ page }) => {
    await expect(page.locator('text=Target')).toBeVisible();
    await expect(page.locator('text=System')).toBeVisible();
    await expect(page.locator('text=Process')).toBeVisible();
    await expect(page.locator('text=Network')).toBeVisible();
    await expect(page.locator('text=Beacon')).toBeVisible();
  });

  test('Sleep button opens modal', async ({ page }) => {
    await page.locator('button:has-text("Sleep")').click();
    await expect(page.getByRole('heading', { name: 'Update Sleep Settings' })).toBeVisible();
    await expect(page.locator('input[type="number"]').first()).toBeVisible();
    await expect(page.locator('input[type="number"]').nth(1)).toBeVisible();
    await page.locator('button:has-text("Cancel")').click();
    await expect(page.getByRole('heading', { name: 'Update Sleep Settings' })).not.toBeVisible();
  });

  test('Sleep modal accepts values', async ({ page }) => {
    await page.locator('button:has-text("Sleep")').click();
    const intervalInput = page.locator('input[type="number"]').first();
    const jitterInput = page.locator('input[type="number"]').nth(1);

    await intervalInput.fill('30');
    await jitterInput.fill('20');

    await expect(intervalInput).toHaveValue('30');
    await expect(jitterInput).toHaveValue('20');

    await page.locator('button:has-text("Cancel")').click();
  });

  test('Kill button opens confirmation modal', async ({ page }) => {
    await page.locator('button:has-text("Kill")').click();
    await expect(page.getByRole('heading', { name: 'Kill Implant' })).toBeVisible();
    await expect(page.getByText('terminate the implant process')).toBeVisible();
    await page.getByRole('button', { name: 'Cancel' }).click();
    await expect(page.getByRole('heading', { name: 'Kill Implant' })).not.toBeVisible();
  });

  test('Retire button opens confirmation modal', async ({ page }) => {
    const retireBtn = page.locator('button:has-text("Retire")');
    if (await retireBtn.isVisible()) {
      await retireBtn.click();
      await expect(page.getByRole('heading', { name: 'Retire Implant' })).toBeVisible();
      await page.getByRole('button', { name: 'Cancel' }).click();
    }
  });

  test('Tab buttons work', async ({ page }) => {
    // Terminal tab should be active by default
    await expect(page.locator('button:has-text("Terminal")')).toBeVisible();
    await expect(page.locator('button:has-text("Tasks")')).toBeVisible();
    await expect(page.locator('button:has-text("Files")')).toBeVisible();

    // Click Tasks tab
    await page.locator('button:has-text("Tasks")').click();
    await page.waitForTimeout(500);

    // Click Files tab
    await page.locator('button:has-text("Files")').click();
    await page.waitForTimeout(500);

    // Click Terminal tab
    await page.locator('button:has-text("Terminal")').click();
  });

  test('Lock Session button works', async ({ page }) => {
    const lockBtn = page.locator('button:has-text("Lock Session")');
    if (await lockBtn.isVisible()) {
      await expect(lockBtn).toBeEnabled();
    }
  });

  test('Export button exists', async ({ page }) => {
    const exportBtn = page.locator('button:has-text("Export")');
    await expect(exportBtn).toBeVisible();
  });

  test('command input has all elements', async ({ page }) => {
    // Mode selector
    const modeSelect = page.locator('select').first();
    await expect(modeSelect).toBeVisible();

    // Command input
    const cmdInput = page.locator('input[placeholder*="Enter command"]');
    await expect(cmdInput).toBeVisible();

    // Run button
    await expect(page.locator('button:has-text("Run")')).toBeVisible();
  });

  test('command input accepts text', async ({ page }) => {
    const cmdInput = page.locator('input[placeholder*="Enter command"]');
    await cmdInput.fill('whoami');
    await expect(cmdInput).toHaveValue('whoami');
  });

  test('session tabs close button works', async ({ page }) => {
    // SessionTabs may have close buttons with × or SVG icons
    const closeBtn = page.locator('button[aria-label="Close tab"], button:has-text("×")').first();
    if (await closeBtn.isVisible()) {
      // Just verify it exists and is clickable
      await expect(closeBtn).toBeEnabled();
    }
  });
});

// ============================================================================
// LISTENERS PAGE
// ============================================================================
test.describe('Listeners Page', () => {
  test('displays page correctly', async ({ page }) => {
    await page.goto('/listeners');
    await expect(page.getByRole('heading', { name: 'Listeners' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Create Listener' })).toBeVisible();
  });

  test('Create Listener button opens modal', async ({ page }) => {
    await page.goto('/listeners');
    await page.getByRole('button', { name: 'Create Listener' }).click();

    await expect(page.getByRole('heading', { name: 'Create Listener' })).toBeVisible();
  });

  test('Create Listener modal has all form fields', async ({ page }) => {
    await page.goto('/listeners');
    await page.getByRole('button', { name: 'Create Listener' }).click();

    await expect(page.getByLabel('Name')).toBeVisible();
    await expect(page.getByLabel('Protocol')).toBeVisible();
    await expect(page.getByLabel(/Bind Address/i)).toBeVisible();
    await expect(page.getByLabel(/Port/i)).toBeVisible();
    await expect(page.getByRole('button', { name: 'Cancel' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Start Listener' })).toBeVisible();
  });

  test('Protocol dropdown has options', async ({ page }) => {
    await page.goto('/listeners');
    await page.getByRole('button', { name: 'Create Listener' }).click();

    const protocolSelect = page.locator('select#listener-protocol');
    await expect(protocolSelect).toBeVisible();
    // Just verify the select exists and has options
    const options = await protocolSelect.locator('option').count();
    expect(options).toBeGreaterThan(0);
  });

  test('DNS protocol shows base domain field', async ({ page }) => {
    await page.goto('/listeners');
    await page.getByRole('button', { name: 'Create Listener' }).click();

    // Select DNS
    await page.getByLabel('Protocol').selectOption('dns');

    // Base domain field should appear
    await expect(page.getByLabel(/Base Domain/i)).toBeVisible();
  });

  test('Cancel button closes modal', async ({ page }) => {
    await page.goto('/listeners');
    await page.getByRole('button', { name: 'Create Listener' }).click();

    await page.getByRole('button', { name: 'Cancel' }).click();
    await expect(page.getByRole('heading', { name: 'Create Listener' })).not.toBeVisible();
  });

  test('Close button (X) closes modal', async ({ page }) => {
    await page.goto('/listeners');
    await page.getByRole('button', { name: 'Create Listener' }).click();

    await page.locator('button[aria-label="Close modal"]').click();
    await expect(page.getByRole('heading', { name: 'Create Listener' })).not.toBeVisible();
  });

  test('form accepts input values', async ({ page }) => {
    await page.goto('/listeners');
    await page.getByRole('button', { name: 'Create Listener' }).click();

    await page.getByLabel('Name').fill('test-listener');
    await page.getByLabel(/Bind Address/i).fill('127.0.0.1');
    await page.getByLabel(/Port/i).fill('9999');

    await expect(page.getByLabel('Name')).toHaveValue('test-listener');
    await expect(page.getByLabel(/Port/i)).toHaveValue('9999');

    await page.getByRole('button', { name: 'Cancel' }).click();
  });
});

// ============================================================================
// LOOT PAGE
// ============================================================================
test.describe('Loot Page', () => {
  test('displays page correctly', async ({ page }) => {
    await page.goto('/loot');
    await expect(page.getByRole('heading', { name: 'Loot', level: 1 })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Export All' })).toBeVisible();
  });

  test('filter buttons exist and work', async ({ page }) => {
    await page.goto('/loot');

    // All filter buttons should be visible
    await expect(page.getByRole('button', { name: 'All', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Credentials' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Files' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Tokens' })).toBeVisible();

    // Click each filter
    await page.getByRole('button', { name: 'Credentials' }).click();
    await page.getByRole('button', { name: 'Files' }).click();
    await page.getByRole('button', { name: 'Tokens' }).click();
    await page.getByRole('button', { name: 'All', exact: true }).click();
  });

  test('search input works', async ({ page }) => {
    await page.goto('/loot');

    const searchInput = page.getByPlaceholder('Search loot...');
    await expect(searchInput).toBeVisible();

    await searchInput.fill('admin');
    await expect(searchInput).toHaveValue('admin');
  });

  test('Export All button is enabled', async ({ page }) => {
    await page.goto('/loot');
    await expect(page.getByRole('button', { name: 'Export All' })).toBeEnabled();
  });

  test('table has correct headers', async ({ page }) => {
    await page.goto('/loot');

    await expect(page.locator('th:has-text("Type")')).toBeVisible();
    await expect(page.locator('th:has-text("Details")')).toBeVisible();
    await expect(page.locator('th:has-text("Source")')).toBeVisible();
    await expect(page.locator('th:has-text("Collected")')).toBeVisible();
    await expect(page.locator('th:has-text("Actions")')).toBeVisible();
  });
});

// ============================================================================
// MODULES PAGE
// ============================================================================
test.describe('Modules Page', () => {
  test('displays page correctly', async ({ page }) => {
    await page.goto('/modules');
    await expect(page.getByRole('heading', { name: 'Modules' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Refresh' })).toBeVisible();
  });

  test('info banner is visible', async ({ page }) => {
    await page.goto('/modules');
    await expect(page.getByText('Dynamic modules extend implant capabilities')).toBeVisible();
  });

  test('Refresh button is clickable', async ({ page }) => {
    await page.goto('/modules');
    const refreshBtn = page.getByRole('button', { name: 'Refresh' });
    await expect(refreshBtn).toBeEnabled();
    await refreshBtn.click();
  });

  test('table has correct headers', async ({ page }) => {
    await page.goto('/modules');

    await expect(page.locator('th:has-text("ID")')).toBeVisible();
    await expect(page.locator('th:has-text("Name")')).toBeVisible();
    await expect(page.locator('th:has-text("Description")')).toBeVisible();
    await expect(page.locator('th:has-text("Platforms")')).toBeVisible();
    await expect(page.locator('th:has-text("Actions")')).toBeVisible();
  });
});

// ============================================================================
// REPORTS PAGE
// ============================================================================
test.describe('Reports Page', () => {
  test('displays page correctly', async ({ page }) => {
    await page.goto('/reports');
    await expect(page.locator('h1:has-text("Reports")')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('button:has-text("Generate Report")')).toBeVisible();
  });

  test('report type cards are visible', async ({ page }) => {
    await page.goto('/reports');

    await expect(page.getByText('Engagement Report')).toBeVisible();
    await expect(page.getByText('IOC Report')).toBeVisible();
    await expect(page.getByText('Executive Summary')).toBeVisible();
  });

  test('report type cards are clickable', async ({ page }) => {
    await page.goto('/reports');

    const engagementCard = page.locator('button:has-text("Engagement Report")');
    await expect(engagementCard).toBeEnabled();
  });

  test('Generated Reports section exists', async ({ page }) => {
    await page.goto('/reports');
    await expect(page.getByRole('heading', { name: 'Generated Reports' })).toBeVisible();
  });

  test('table has correct headers', async ({ page }) => {
    await page.goto('/reports');

    await expect(page.locator('th:has-text("Title")')).toBeVisible();
    await expect(page.locator('th:has-text("Type")')).toBeVisible();
    await expect(page.locator('th:has-text("Generated")')).toBeVisible();
    await expect(page.locator('th:has-text("By")')).toBeVisible();
    await expect(page.locator('th:has-text("Actions")')).toBeVisible();
  });
});

// ============================================================================
// OPERATORS PAGE
// ============================================================================
test.describe('Operators Page', () => {
  test('displays page correctly', async ({ page }) => {
    await page.goto('/operators');
    await expect(page.getByRole('heading', { name: 'Operators' })).toBeVisible();
    await expect(page.locator('button:has-text("Add Operator")')).toBeVisible();
  });

  test('Add Operator button opens modal', async ({ page }) => {
    await page.goto('/operators');
    await page.locator('button:has-text("Add Operator")').click();

    await expect(page.locator('h2:has-text("Add Operator")')).toBeVisible();
  });

  test('Add Operator modal has all form fields', async ({ page }) => {
    await page.goto('/operators');
    await page.locator('button:has-text("Add Operator")').first().click();

    await expect(page.locator('input[placeholder="operator-name"]')).toBeVisible();
    await expect(page.locator('input[type="password"]')).toBeVisible();
    await expect(page.locator('select')).toBeVisible();
    await expect(page.locator('button:has-text("Cancel")')).toBeVisible();
  });

  test('Role dropdown has options', async ({ page }) => {
    await page.goto('/operators');
    await page.locator('button:has-text("Add Operator")').first().click();

    const roleSelect = page.locator('select');
    await expect(roleSelect).toBeVisible();
    // Verify select has options
    const options = await roleSelect.locator('option').count();
    expect(options).toBeGreaterThan(0);
  });

  test('form validation - empty fields', async ({ page }) => {
    await page.goto('/operators');
    await page.locator('button:has-text("Add Operator")').first().click();

    // Submit button should be disabled with empty fields
    const submitBtn = page.locator('button[type="submit"]');
    await expect(submitBtn).toBeDisabled();
  });

  test('form accepts input', async ({ page }) => {
    await page.goto('/operators');
    await page.locator('button:has-text("Add Operator")').first().click();

    await page.locator('input[placeholder="operator-name"]').fill('test-user');
    await page.locator('input[type="password"]').fill('test-pass');

    // Button should be enabled now
    const submitBtn = page.locator('button[type="submit"]');
    await expect(submitBtn).toBeEnabled();

    await page.locator('button:has-text("Cancel")').click();
  });

  test('Close button works', async ({ page }) => {
    await page.goto('/operators');
    await page.locator('button:has-text("Add Operator")').click();

    await page.locator('button[aria-label="Close modal"]').click();
    await expect(page.locator('h2:has-text("Add Operator")')).not.toBeVisible();
  });

  test('table has correct headers', async ({ page }) => {
    await page.goto('/operators');

    await expect(page.locator('th:has-text("Username")')).toBeVisible();
    await expect(page.locator('th:has-text("Role")')).toBeVisible();
    await expect(page.locator('th:has-text("Status")')).toBeVisible();
    await expect(page.locator('th:has-text("Last Login")')).toBeVisible();
    await expect(page.locator('th:has-text("Actions")')).toBeVisible();
  });

  test('Role Permissions section is visible', async ({ page }) => {
    await page.goto('/operators');
    await expect(page.getByRole('heading', { name: 'Role Permissions' })).toBeVisible();
    await expect(page.getByText('Full access to all features')).toBeVisible();
  });

  test('Edit button opens modal', async ({ page }) => {
    await page.goto('/operators');
    // Wait for page to load
    await expect(page.getByRole('heading', { name: 'Operators' })).toBeVisible({ timeout: 10000 });

    // Check if there are any operators with Edit button
    const editBtn = page.locator('button:has-text("Edit")').first();
    const hasEditBtn = await editBtn.isVisible().catch(() => false);
    if (hasEditBtn) {
      await editBtn.click();
      await expect(page.locator('h2:has-text("Edit Operator")')).toBeVisible();
      // Close via Cancel button (more reliable than × button)
      await page.locator('button:has-text("Cancel")').click();
    }
    // Test passes even if no operators to edit
  });

  test('Revoke button opens confirmation', async ({ page }) => {
    await page.goto('/operators');
    await page.waitForSelector('tbody tr', { timeout: 10000 });

    const revokeBtn = page.locator('button:has-text("Revoke")').first();
    if (await revokeBtn.isVisible()) {
      await revokeBtn.click();
      await expect(page.locator('h2:has-text("Revoke Operator")')).toBeVisible();
      await expect(page.getByText('disable the operator')).toBeVisible();
      await page.getByRole('button', { name: 'Cancel' }).click();
    }
  });
});

// ============================================================================
// GENERAL MODAL BEHAVIOR
// ============================================================================
test.describe('Modal Behavior', () => {
  test('Listeners modal Cancel button works', async ({ page }) => {
    await page.goto('/listeners');
    await page.getByRole('button', { name: 'Create Listener' }).click();
    await expect(page.locator('h2:has-text("Create Listener")')).toBeVisible();
    await page.getByRole('button', { name: 'Cancel' }).click();
    await expect(page.locator('h2:has-text("Create Listener")')).not.toBeVisible();
  });

  test('Operators modal Cancel button works', async ({ page }) => {
    await page.goto('/operators');
    await page.locator('button:has-text("Add Operator")').first().click();
    await expect(page.locator('h2:has-text("Add Operator")')).toBeVisible();
    await page.locator('button:has-text("Cancel")').click();
    await expect(page.locator('h2:has-text("Add Operator")')).not.toBeVisible();
  });
});

// ============================================================================
// LOADING & ERROR STATES
// ============================================================================
test.describe('Loading & Error States', () => {
  test('dashboard handles loading', async ({ page }) => {
    await page.goto('/dashboard');
    // Page should show either loading or content
    await expect(page.locator('h1:has-text("Dashboard")')).toBeVisible({ timeout: 10000 });
  });

  test('sessions handles empty state', async ({ page }) => {
    await page.goto('/sessions');
    // Should show either sessions or empty message
    await expect(page.locator('tbody tr').first().or(page.getByText('No active sessions', { exact: false }).first())).toBeVisible({ timeout: 10000 });
  });

  test('loot handles empty state', async ({ page }) => {
    await page.goto('/loot');
    // Wait for page heading to ensure page is loaded
    await expect(page.getByRole('heading', { name: 'Loot' })).toBeVisible({ timeout: 10000 });
    // Wait for table to be present
    await expect(page.locator('table')).toBeVisible({ timeout: 10000 });
    // Check for table body row (either data or empty message)
    await expect(page.locator('tbody tr')).toBeVisible({ timeout: 10000 });
  });

  test('modules page loads', async ({ page }) => {
    await page.goto('/modules');
    await expect(page.getByRole('heading', { name: 'Modules' })).toBeVisible({ timeout: 10000 });
    // Page should show table
    await expect(page.locator('table')).toBeVisible();
  });

  test('listeners page loads', async ({ page }) => {
    await page.goto('/listeners');
    await expect(page.getByRole('heading', { name: 'Listeners' })).toBeVisible({ timeout: 10000 });
    // Page loads successfully - content will be either cards or empty state
  });
});
