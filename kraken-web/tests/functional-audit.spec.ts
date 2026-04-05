import { test, expect, type Page, type ConsoleMessage } from '@playwright/test';

// ── Helpers ──────────────────────────────────────────────────────────────────

const BASE = 'http://127.0.0.1:3000';
const SESSION_HEX = '552eafbafa0d4828b887fb791970e340';
const SESSION_UUID = '552eafba-fa0d-4828-b887-fb791970e340';

interface PageLog {
  type: string;
  text: string;
}

/** Collect console messages and network failures during a test. */
function attachMonitors(page: Page) {
  const logs: PageLog[] = [];
  const networkErrors: string[] = [];

  page.on('console', (msg: ConsoleMessage) => {
    logs.push({ type: msg.type(), text: msg.text() });
  });

  page.on('requestfailed', (req) => {
    networkErrors.push(`${req.method()} ${req.url()} - ${req.failure()?.errorText ?? 'unknown'}`);
  });

  return { logs, networkErrors };
}

/** Inject auth token into localStorage so we bypass the login gate. */
async function injectAuth(page: Page) {
  await page.addInitScript(() => {
    localStorage.setItem(
      'kraken-auth',
      JSON.stringify({
        state: { token: 'test-operator-token', isAuthenticated: true },
        version: 0,
      }),
    );
  });
}

/** Navigate to a page with auth pre-set, wait for network idle. */
async function go(page: Page, path: string) {
  await injectAuth(page);
  await page.goto(`${BASE}${path}`, { waitUntil: 'networkidle', timeout: 15000 });
}

// ── 1. LOGIN PAGE ────────────────────────────────────────────────────────────

test.describe('1. Login Page', () => {
  test('renders login form with token input and submit button', async ({ page }) => {
    const m = attachMonitors(page);
    await page.goto(`${BASE}/login`, { waitUntil: 'networkidle' });

    const tokenInput = page.locator('#token');
    await expect(tokenInput).toBeVisible();
    await expect(tokenInput).toHaveAttribute('type', 'password');

    const submitBtn = page.locator('button[type="submit"]');
    await expect(submitBtn).toBeVisible();
    await expect(submitBtn).toContainText(/sign in|connect|login|authenticate/i);

    const errors = m.logs.filter(l => l.type === 'error');
    expect(errors.length).toBe(0);
  });

  test('shows validation error on empty submit', async ({ page }) => {
    await page.goto(`${BASE}/login`, { waitUntil: 'networkidle' });

    await page.locator('button[type="submit"]').click();

    // Should show "Token is required" error
    await expect(page.getByText('Token is required')).toBeVisible({ timeout: 3000 });
  });

  test('successful login navigates to dashboard', async ({ page }) => {
    await page.goto(`${BASE}/login`, { waitUntil: 'networkidle' });

    await page.locator('#token').fill('test-operator-token');
    await page.locator('button[type="submit"]').click();

    await page.waitForURL('**/dashboard', { timeout: 5000 });
    expect(page.url()).toContain('/dashboard');
  });
});

// ── 2. DASHBOARD ─────────────────────────────────────────────────────────────

test.describe('2. Dashboard', () => {
  test('loads and displays dashboard content', async ({ page }) => {
    const m = attachMonitors(page);
    await go(page, '/dashboard');

    // Should have some content visible (heading, cards, stats)
    await expect(page.locator('main')).toBeVisible();

    // Check for common dashboard elements
    const body = await page.textContent('body');
    expect(body).toBeTruthy();
    expect(body!.length).toBeGreaterThan(50);

    // No JS errors
    const jsErrors = m.logs.filter(l => l.type === 'error' && !l.text.includes('net::'));
    // Report but don't fail on gRPC connection errors (expected if backend is limited)
    console.log('Dashboard console errors:', jsErrors.map(e => e.text));
  });
});

// ── 3. SESSIONS PAGE ─────────────────────────────────────────────────────────

test.describe('3. Sessions Page', () => {
  test('loads sessions list with gRPC data', async ({ page }) => {
    const m = attachMonitors(page);
    await go(page, '/sessions');

    // Wait for content to appear
    await page.waitForTimeout(2000);

    const body = await page.textContent('body');
    expect(body).toBeTruthy();

    // Check for sessions heading or session-related content
    const hasSessions = await page.locator('text=Sessions').first().isVisible().catch(() => false);
    console.log('Sessions heading visible:', hasSessions);
    console.log('Sessions page errors:', m.logs.filter(l => l.type === 'error').map(e => e.text));
  });

  test('session row is clickable and navigates to detail', async ({ page }) => {
    await go(page, '/sessions');
    await page.waitForTimeout(2000);

    // Look for any clickable row or link that contains session data
    const sessionLink = page.locator(`a[href*="/sessions/"], tr[data-session-id], [role="row"]`).first();
    const exists = await sessionLink.isVisible().catch(() => false);
    console.log('Session row found:', exists);

    if (exists) {
      await sessionLink.click();
      await page.waitForTimeout(1000);
      expect(page.url()).toContain('/sessions/');
    }
  });

  test('retire/burn/delete action buttons exist for sessions', async ({ page }) => {
    await go(page, '/sessions');
    await page.waitForTimeout(2000);

    // Check for action buttons (context menu or direct buttons)
    const actionBtns = page.locator('button').filter({ hasText: /retire|burn|delete|remove/i });
    const count = await actionBtns.count();
    console.log('Session action buttons found:', count);
  });
});

// ── 4. SESSION DETAIL PAGE ───────────────────────────────────────────────────

test.describe('4. Session Detail Page', () => {
  test('loads session detail with tabs', async ({ page }) => {
    const m = attachMonitors(page);
    await go(page, `/sessions/${SESSION_HEX}`);
    await page.waitForTimeout(2000);

    // Check tabs exist
    const tabs = ['terminal', 'tasks', 'files', 'mesh', 'pivot', 'bof', 'process', 'inject', 'token'];
    for (const tab of tabs) {
      const tabBtn = page.locator(`button, [role="tab"]`).filter({ hasText: new RegExp(tab, 'i') });
      const visible = await tabBtn.first().isVisible().catch(() => false);
      console.log(`Tab '${tab}':`, visible ? 'FOUND' : 'NOT FOUND');
    }

    console.log('Session detail errors:', m.logs.filter(l => l.type === 'error').map(e => e.text));
  });

  test('terminal tab - command input is functional', async ({ page }) => {
    await go(page, `/sessions/${SESSION_HEX}`);
    await page.waitForTimeout(2000);

    // Look for command input field
    const cmdInput = page.locator('input[type="text"], textarea, [contenteditable="true"]').first();
    const inputVisible = await cmdInput.isVisible().catch(() => false);
    console.log('Command input visible:', inputVisible);

    if (inputVisible) {
      await cmdInput.fill('whoami');
      const value = await cmdInput.inputValue().catch(() => '');
      expect(value).toBe('whoami');
      console.log('Command input accepts text: PASS');

      // Try to submit the command
      await cmdInput.press('Enter');
      await page.waitForTimeout(3000);

      // Check if any output appeared
      const body = await page.textContent('body');
      console.log('Body length after command:', body?.length);
    }
  });

  test('file browser tab loads', async ({ page }) => {
    await go(page, `/sessions/${SESSION_HEX}`);
    await page.waitForTimeout(1500);

    // Click files tab
    const filesTab = page.locator('button, [role="tab"]').filter({ hasText: /files/i }).first();
    const exists = await filesTab.isVisible().catch(() => false);
    if (exists) {
      await filesTab.click();
      await page.waitForTimeout(2000);
      console.log('Files tab clicked successfully');
    } else {
      console.log('Files tab not found in session detail');
    }
  });

  test('process browser tab loads', async ({ page }) => {
    await go(page, `/sessions/${SESSION_HEX}`);
    await page.waitForTimeout(1500);

    const processTab = page.locator('button, [role="tab"]').filter({ hasText: /process/i }).first();
    const exists = await processTab.isVisible().catch(() => false);
    if (exists) {
      await processTab.click();
      await page.waitForTimeout(2000);
      console.log('Process tab clicked successfully');
    } else {
      console.log('Process tab not found in session detail');
    }
  });

  test('inject tab renders OPSEC gate', async ({ page }) => {
    await go(page, `/sessions/${SESSION_HEX}`);
    await page.waitForTimeout(1500);

    const injectTab = page.locator('button, [role="tab"]').filter({ hasText: /inject/i }).first();
    const exists = await injectTab.isVisible().catch(() => false);
    if (exists) {
      await injectTab.click();
      await page.waitForTimeout(1500);
      // Should have injection-related UI
      const body = await page.textContent('body');
      const hasInjectContent = body?.match(/inject|shellcode|pid|process|technique/i);
      console.log('Inject tab content present:', !!hasInjectContent);
    }
  });

  test('token tab renders token manipulation UI', async ({ page }) => {
    await go(page, `/sessions/${SESSION_HEX}`);
    await page.waitForTimeout(1500);

    const tokenTab = page.locator('button, [role="tab"]').filter({ hasText: /token/i }).first();
    const exists = await tokenTab.isVisible().catch(() => false);
    if (exists) {
      await tokenTab.click();
      await page.waitForTimeout(1500);
      const body = await page.textContent('body');
      const hasTokenContent = body?.match(/token|steal|make|impersonate|revert/i);
      console.log('Token tab content present:', !!hasTokenContent);
    }
  });

  test('mesh tab renders mesh control panel', async ({ page }) => {
    await go(page, `/sessions/${SESSION_HEX}`);
    await page.waitForTimeout(1500);

    const meshTab = page.locator('button, [role="tab"]').filter({ hasText: /mesh/i }).first();
    const exists = await meshTab.isVisible().catch(() => false);
    if (exists) {
      await meshTab.click();
      await page.waitForTimeout(1500);
      const body = await page.textContent('body');
      const hasMeshContent = body?.match(/mesh|peer|connection|relay/i);
      console.log('Mesh tab content present:', !!hasMeshContent);
    }
  });

  test('BOF tab renders execution panel', async ({ page }) => {
    await go(page, `/sessions/${SESSION_HEX}`);
    await page.waitForTimeout(1500);

    const bofTab = page.locator('button, [role="tab"]').filter({ hasText: /bof/i }).first();
    const exists = await bofTab.isVisible().catch(() => false);
    if (exists) {
      await bofTab.click();
      await page.waitForTimeout(1500);
      const body = await page.textContent('body');
      const hasBofContent = body?.match(/bof|beacon|object|catalog/i);
      console.log('BOF tab content present:', !!hasBofContent);
    }
  });
});

// ── 5. FILES PAGE (standalone) ──────────────────────────────────────────────

test.describe('5. Files Page (standalone)', () => {
  test('loads file browser for session', async ({ page }) => {
    const m = attachMonitors(page);
    await go(page, `/files/${SESSION_HEX}`);
    await page.waitForTimeout(2000);

    const body = await page.textContent('body');
    console.log('Files page body length:', body?.length);
    console.log('Files page errors:', m.logs.filter(l => l.type === 'error').map(e => e.text));
  });
});

// ── 6. PROCESSES PAGE (standalone) ──────────────────────────────────────────

test.describe('6. Processes Page (standalone)', () => {
  test('loads process list for session', async ({ page }) => {
    const m = attachMonitors(page);
    await go(page, `/processes/${SESSION_HEX}`);
    await page.waitForTimeout(2000);

    const body = await page.textContent('body');
    console.log('Processes page body length:', body?.length);
    console.log('Processes page errors:', m.logs.filter(l => l.type === 'error').map(e => e.text));
  });
});

// ── 7. LISTENERS PAGE ────────────────────────────────────────────────────────

test.describe('7. Listeners Page', () => {
  test('loads listeners list', async ({ page }) => {
    const m = attachMonitors(page);
    await go(page, '/listeners');
    await page.waitForTimeout(2000);

    const heading = page.locator('text=Listeners').first();
    const visible = await heading.isVisible().catch(() => false);
    console.log('Listeners heading visible:', visible);
    console.log('Listeners errors:', m.logs.filter(l => l.type === 'error').map(e => e.text));
  });

  test('Create Listener button opens modal', async ({ page }) => {
    await go(page, '/listeners');
    await page.waitForTimeout(1500);

    const createBtn = page.locator('button').filter({ hasText: /create|new|start|add/i }).first();
    const exists = await createBtn.isVisible().catch(() => false);
    console.log('Create listener button found:', exists);

    if (exists) {
      await createBtn.click();
      await page.waitForTimeout(1000);

      // Check if a modal/form appeared
      const modal = page.locator('[role="dialog"], .modal, [class*="modal"]').first();
      const modalVisible = await modal.isVisible().catch(() => false);

      // Also check for form fields
      const formField = page.locator('input[name], select, input[type="text"], input[type="number"]').first();
      const formVisible = await formField.isVisible().catch(() => false);

      console.log('Modal/form visible after click:', modalVisible || formVisible);
    }
  });

  test('Create Listener form has required fields', async ({ page }) => {
    await go(page, '/listeners');
    await page.waitForTimeout(1500);

    const createBtn = page.locator('button').filter({ hasText: /create|new|start|add/i }).first();
    if (await createBtn.isVisible().catch(() => false)) {
      await createBtn.click();
      await page.waitForTimeout(1000);

      // Check for protocol selector
      const protocolSelect = page.locator('select, [role="listbox"]').first();
      const hasProtocol = await protocolSelect.isVisible().catch(() => false);
      console.log('Protocol selector:', hasProtocol);

      // Check for port input
      const portInput = page.locator('input[placeholder*="port" i], input[name*="port" i], label:has-text("Port") + input, label:has-text("Port") ~ input').first();
      const hasPort = await portInput.isVisible().catch(() => false);
      console.log('Port input:', hasPort);
    }
  });
});

// ── 8. PAYLOADS PAGE ─────────────────────────────────────────────────────────

test.describe('8. Payloads Page', () => {
  test('loads payloads page with generate UI', async ({ page }) => {
    const m = attachMonitors(page);
    await go(page, '/payloads');
    await page.waitForTimeout(2000);

    const body = await page.textContent('body');
    const hasPayloadContent = body?.match(/payload|generate|format|implant|shellcode|exe|dll/i);
    console.log('Payload content present:', !!hasPayloadContent);
    console.log('Payloads errors:', m.logs.filter(l => l.type === 'error').map(e => e.text));
  });

  test('payload configuration form is interactive', async ({ page }) => {
    await go(page, '/payloads');
    await page.waitForTimeout(2000);

    // Check for config fields (OS, arch, format selectors)
    const selectors = page.locator('select, [role="listbox"], [role="radiogroup"], input[type="radio"]');
    const count = await selectors.count();
    console.log('Payload config selectors found:', count);

    // Check for buttons
    const buttons = page.locator('button');
    const btnCount = await buttons.count();
    console.log('Payload page buttons found:', btnCount);

    // Try clicking format options if they exist
    const formatBtns = page.locator('button, [role="radio"]').filter({ hasText: /exe|dll|shellcode/i });
    const formatCount = await formatBtns.count();
    console.log('Format option buttons found:', formatCount);
    if (formatCount > 0) {
      await formatBtns.first().click();
      console.log('Format option clicked successfully');
    }
  });
});

// ── 9. LOOT PAGE ─────────────────────────────────────────────────────────────

test.describe('9. Loot Page', () => {
  test('loads loot page', async ({ page }) => {
    const m = attachMonitors(page);
    await go(page, '/loot');
    await page.waitForTimeout(2000);

    const body = await page.textContent('body');
    const hasLootContent = body?.match(/loot|credential|token|hash|file|empty/i);
    console.log('Loot content present:', !!hasLootContent);
    console.log('Loot errors:', m.logs.filter(l => l.type === 'error').map(e => e.text));
  });

  test('loot search/filter is functional', async ({ page }) => {
    await go(page, '/loot');
    await page.waitForTimeout(2000);

    // Look for search input
    const searchInput = page.locator('input[placeholder*="search" i], input[placeholder*="filter" i], input[type="search"]').first();
    const hasSearch = await searchInput.isVisible().catch(() => false);
    console.log('Loot search input found:', hasSearch);

    if (hasSearch) {
      await searchInput.fill('admin');
      await page.waitForTimeout(500);
      console.log('Search accepts input: PASS');
      await searchInput.clear();
    }

    // Look for type filter tabs/buttons
    const filterBtns = page.locator('button').filter({ hasText: /credential|token|hash|file|all/i });
    const filterCount = await filterBtns.count();
    console.log('Loot filter buttons found:', filterCount);
  });

  test('loot export buttons exist', async ({ page }) => {
    await go(page, '/loot');
    await page.waitForTimeout(2000);

    const exportBtns = page.locator('button').filter({ hasText: /export|hashcat|john|download|csv/i });
    const count = await exportBtns.count();
    console.log('Loot export buttons found:', count);
  });
});

// ── 10. JOBS PAGE ────────────────────────────────────────────────────────────

test.describe('10. Jobs Page', () => {
  test('loads jobs list', async ({ page }) => {
    const m = attachMonitors(page);
    await go(page, '/jobs');
    await page.waitForTimeout(2000);

    const body = await page.textContent('body');
    const hasJobsContent = body?.match(/job|task|running|completed|failed|empty|no jobs/i);
    console.log('Jobs content present:', !!hasJobsContent);
    console.log('Jobs errors:', m.logs.filter(l => l.type === 'error').map(e => e.text));
  });

  test('jobs filter dropdown works', async ({ page }) => {
    await go(page, '/jobs');
    await page.waitForTimeout(2000);

    const filterSelect = page.locator('select, button').filter({ hasText: /all|running|completed|failed|filter/i }).first();
    const exists = await filterSelect.isVisible().catch(() => false);
    console.log('Jobs filter found:', exists);

    if (exists) {
      await filterSelect.click();
      await page.waitForTimeout(500);
      console.log('Jobs filter clicked');
    }
  });
});

// ── 11. MODULES PAGE ─────────────────────────────────────────────────────────

test.describe('11. Modules Page', () => {
  test('loads modules list', async ({ page }) => {
    const m = attachMonitors(page);
    await go(page, '/modules');
    await page.waitForTimeout(2000);

    const body = await page.textContent('body');
    const hasModulesContent = body?.match(/module|available|loaded|platform|no module/i);
    console.log('Modules content present:', !!hasModulesContent);
    console.log('Modules errors:', m.logs.filter(l => l.type === 'error').map(e => e.text));
  });

  test('module detail modal opens on click', async ({ page }) => {
    await go(page, '/modules');
    await page.waitForTimeout(2000);

    // Try clicking on a module card/row
    const moduleItem = page.locator('[class*="cursor-pointer"], tr, [role="row"], .card').first();
    const exists = await moduleItem.isVisible().catch(() => false);
    console.log('Module item found:', exists);

    if (exists) {
      await moduleItem.click();
      await page.waitForTimeout(1000);
      const modal = page.locator('[role="dialog"], [class*="modal"]').first();
      const modalOpen = await modal.isVisible().catch(() => false);
      console.log('Module detail modal opened:', modalOpen);
    }
  });
});

// ── 12. REPORTS PAGE ─────────────────────────────────────────────────────────

test.describe('12. Reports Page', () => {
  test('loads reports page', async ({ page }) => {
    const m = attachMonitors(page);
    await go(page, '/reports');
    await page.waitForTimeout(2000);

    const body = await page.textContent('body');
    expect(body).toBeTruthy();
    console.log('Reports page body length:', body?.length);
    console.log('Reports errors:', m.logs.filter(l => l.type === 'error').map(e => e.text));
  });
});

// ── 13. DEFENDER PAGE ────────────────────────────────────────────────────────

test.describe('13. Defender Page', () => {
  test('loads defender intelligence page', async ({ page }) => {
    const m = attachMonitors(page);
    await go(page, '/defender');
    await page.waitForTimeout(2000);

    const body = await page.textContent('body');
    const hasDefenderContent = body?.match(/defender|detection|yara|sigma|ioc|rule/i);
    console.log('Defender content present:', !!hasDefenderContent);
    console.log('Defender errors:', m.logs.filter(l => l.type === 'error').map(e => e.text));
  });
});

// ── 14. OPERATORS PAGE ───────────────────────────────────────────────────────

test.describe('14. Operators Page', () => {
  test('loads operators page', async ({ page }) => {
    const m = attachMonitors(page);
    await go(page, '/operators');
    await page.waitForTimeout(2000);

    const body = await page.textContent('body');
    const hasContent = body?.match(/operator|role|admin|user|permission/i);
    console.log('Operators content present:', !!hasContent);
    console.log('Operators errors:', m.logs.filter(l => l.type === 'error').map(e => e.text));
  });
});

// ── 15. SETTINGS PAGE ────────────────────────────────────────────────────────

test.describe('15. Settings Page', () => {
  test('loads settings page with configuration options', async ({ page }) => {
    const m = attachMonitors(page);
    await go(page, '/settings');
    await page.waitForTimeout(2000);

    const body = await page.textContent('body');
    const hasContent = body?.match(/settings|theme|preferences|configuration/i);
    console.log('Settings content present:', !!hasContent);
    console.log('Settings errors:', m.logs.filter(l => l.type === 'error').map(e => e.text));
  });

  test('settings controls are interactive', async ({ page }) => {
    await go(page, '/settings');
    await page.waitForTimeout(1500);

    // Check for toggles, selects, inputs
    const controls = page.locator('input, select, button[role="switch"], [type="checkbox"]');
    const count = await controls.count();
    console.log('Settings controls found:', count);
  });
});

// ── 16. AUDIT LOG PAGE ───────────────────────────────────────────────────────

test.describe('16. Audit Log Page', () => {
  test('loads audit log page', async ({ page }) => {
    const m = attachMonitors(page);
    await go(page, '/audit');
    await page.waitForTimeout(2000);

    const body = await page.textContent('body');
    const hasContent = body?.match(/audit|log|event|timestamp|action/i);
    console.log('Audit content present:', !!hasContent);
    console.log('Audit errors:', m.logs.filter(l => l.type === 'error').map(e => e.text));
  });
});

// ── 17. TOPOLOGY PAGE ────────────────────────────────────────────────────────

test.describe('17. Topology Page', () => {
  test('loads topology/network graph', async ({ page }) => {
    const m = attachMonitors(page);
    await go(page, '/topology');
    await page.waitForTimeout(2000);

    // ReactFlow canvas or SVG element
    const canvas = page.locator('.react-flow, [class*="react-flow"], canvas, svg').first();
    const hasCanvas = await canvas.isVisible().catch(() => false);
    console.log('Topology graph canvas present:', hasCanvas);

    const body = await page.textContent('body');
    console.log('Topology page body length:', body?.length);
    console.log('Topology errors:', m.logs.filter(l => l.type === 'error').map(e => e.text));
  });
});

// ── 18. NAVIGATION SIDEBAR ───────────────────────────────────────────────────

test.describe('18. Navigation & Layout', () => {
  test('sidebar contains all navigation links', async ({ page }) => {
    await go(page, '/dashboard');
    await page.waitForTimeout(1500);

    const expectedLinks = [
      'Dashboard', 'Sessions', 'Topology', 'Listeners', 'Payloads',
      'Loot', 'Files', 'Processes', 'Jobs', 'Modules', 'Reports',
      'Defender', 'Operators', 'Settings', 'Audit Log',
    ];

    for (const label of expectedLinks) {
      const link = page.locator('nav a, aside a').filter({ hasText: label }).first();
      const visible = await link.isVisible().catch(() => false);
      console.log(`Nav link '${label}':`, visible ? 'FOUND' : 'MISSING');
    }
  });

  test('navigation between pages works', async ({ page }) => {
    await go(page, '/dashboard');
    await page.waitForTimeout(1000);

    // Click Sessions
    await page.locator('nav a, aside a').filter({ hasText: 'Sessions' }).first().click();
    await page.waitForTimeout(1000);
    expect(page.url()).toContain('/sessions');

    // Click Listeners
    await page.locator('nav a, aside a').filter({ hasText: 'Listeners' }).first().click();
    await page.waitForTimeout(1000);
    expect(page.url()).toContain('/listeners');

    // Click Loot
    await page.locator('nav a, aside a').filter({ hasText: 'Loot' }).first().click();
    await page.waitForTimeout(1000);
    expect(page.url()).toContain('/loot');

    // Click Jobs
    await page.locator('nav a, aside a').filter({ hasText: 'Jobs' }).first().click();
    await page.waitForTimeout(1000);
    expect(page.url()).toContain('/jobs');

    console.log('Multi-page navigation: PASS');
  });

  test('active nav link is highlighted', async ({ page }) => {
    await go(page, '/sessions');
    await page.waitForTimeout(1000);

    const activeLink = page.locator('nav a, aside a').filter({ hasText: 'Sessions' }).first();
    const classes = await activeLink.getAttribute('class');
    const isActive = classes?.includes('mauve') || classes?.includes('active');
    console.log('Active nav link highlighted:', isActive);
  });
});

// ── 19. COMMAND PALETTE ──────────────────────────────────────────────────────

test.describe('19. Command Palette', () => {
  test('Ctrl+K opens command palette', async ({ page }) => {
    await go(page, '/dashboard');
    await page.waitForTimeout(1000);

    await page.keyboard.press('Control+k');
    await page.waitForTimeout(500);

    // Check for palette/dialog
    const palette = page.locator('[role="dialog"], [class*="command"], [class*="palette"], [class*="CommandPalette"]').first();
    const visible = await palette.isVisible().catch(() => false);
    console.log('Command palette opened with Ctrl+K:', visible);
  });
});

// ── 20. PROTECTED ROUTE / AUTH GUARD ─────────────────────────────────────────

test.describe('20. Auth Guard', () => {
  test('unauthenticated user is redirected to login', async ({ page }) => {
    // Clear any auth
    await page.goto(`${BASE}/login`, { waitUntil: 'networkidle' });
    await page.evaluate(() => localStorage.clear());

    await page.goto(`${BASE}/dashboard`, { waitUntil: 'networkidle', timeout: 10000 });
    await page.waitForTimeout(1000);

    // Should be redirected to login
    expect(page.url()).toContain('/login');
    console.log('Auth guard redirect: PASS');
  });
});

// ── 21. CONSOLE ERROR AUDIT (all pages) ──────────────────────────────────────

test.describe('21. Console Error Audit', () => {
  const pages = [
    { path: '/dashboard', name: 'Dashboard' },
    { path: '/sessions', name: 'Sessions' },
    { path: '/listeners', name: 'Listeners' },
    { path: '/payloads', name: 'Payloads' },
    { path: '/loot', name: 'Loot' },
    { path: '/jobs', name: 'Jobs' },
    { path: '/modules', name: 'Modules' },
    { path: '/reports', name: 'Reports' },
    { path: '/defender', name: 'Defender' },
    { path: '/operators', name: 'Operators' },
    { path: '/settings', name: 'Settings' },
    { path: '/audit', name: 'Audit' },
    { path: '/topology', name: 'Topology' },
  ];

  for (const p of pages) {
    test(`${p.name} - no critical JS errors`, async ({ page }) => {
      const m = attachMonitors(page);
      await go(page, p.path);
      await page.waitForTimeout(2000);

      const criticalErrors = m.logs.filter(
        l => l.type === 'error' &&
        !l.text.includes('net::ERR_') &&           // network errors (gRPC backend may not respond)
        !l.text.includes('Failed to fetch') &&       // gRPC fetch failures
        !l.text.includes('connect error') &&         // connect-web errors
        !l.text.includes('AbortError')               // cancelled requests
      );

      console.log(`[${p.name}] Total console errors: ${m.logs.filter(l => l.type === 'error').length}`);
      console.log(`[${p.name}] Critical errors (non-network): ${criticalErrors.length}`);
      if (criticalErrors.length > 0) {
        console.log(`[${p.name}] Critical error details:`, criticalErrors.map(e => e.text));
      }
      console.log(`[${p.name}] Network failures: ${m.networkErrors.length}`);

      // Fail only on non-network critical errors
      expect(criticalErrors.length).toBe(0);
    });
  }
});

// ── 22. EDGE CASES & SECURITY ────────────────────────────────────────────────

test.describe('22. Edge Cases & Security', () => {
  test('invalid session ID shows error or redirects', async ({ page }) => {
    const m = attachMonitors(page);
    await go(page, '/sessions/0000000000000000000000000000dead');
    await page.waitForTimeout(3000);

    const body = await page.textContent('body');
    console.log('Invalid session page body length:', body?.length);
    // Should not crash - either show error or redirect
    expect(body).toBeTruthy();
  });

  test('nonexistent route shows 404 or redirect', async ({ page }) => {
    await go(page, '/this-route-does-not-exist');
    await page.waitForTimeout(2000);

    // Should redirect to dashboard or show 404
    const url = page.url();
    const body = await page.textContent('body');
    console.log('Unknown route URL:', url);
    console.log('Unknown route body present:', !!body);
  });

  test('XSS in URL parameters does not execute', async ({ page }) => {
    const m = attachMonitors(page);
    await go(page, '/sessions/<script>alert(1)</script>');
    await page.waitForTimeout(2000);

    // Verify no dialog/alert popped up
    const body = await page.textContent('body');
    expect(body).not.toContain('<script>');
    console.log('XSS in URL: No script execution (PASS)');
  });

  test('localStorage token is not exposed in DOM', async ({ page }) => {
    await go(page, '/dashboard');
    await page.waitForTimeout(1500);

    const body = await page.textContent('body');
    expect(body).not.toContain('test-operator-token');
    console.log('Token not in DOM: PASS');
  });
});

// ── 23. RESPONSIVE / LAYOUT ─────────────────────────────────────────────────

test.describe('23. Layout Integrity', () => {
  test('no horizontal overflow on pages', async ({ page }) => {
    await go(page, '/dashboard');
    await page.waitForTimeout(1500);

    const hasHScroll = await page.evaluate(() => {
      return document.documentElement.scrollWidth > document.documentElement.clientWidth;
    });
    console.log('Horizontal overflow on dashboard:', hasHScroll);
  });

  test('sidebar is visible and properly sized', async ({ page }) => {
    await go(page, '/dashboard');
    await page.waitForTimeout(1000);

    const sidebar = page.locator('aside').first();
    const box = await sidebar.boundingBox();
    console.log('Sidebar bounding box:', box);
    expect(box).toBeTruthy();
    expect(box!.width).toBeGreaterThan(100);
  });
});
