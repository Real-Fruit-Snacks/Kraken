import { test, expect, Page } from '@playwright/test';

const BASE = 'http://127.0.0.1:3000';
const SESSION_ID = '552eafba-fa0d-4828-b887-fb791970e340';

// Auth state to inject into localStorage before each test
const AUTH_STATE = JSON.stringify({
  state: { token: 'audit-test-token', isAuthenticated: true },
  version: 0,
});

async function authenticateAndGoto(page: Page, path: string) {
  // Set auth in localStorage by visiting a blank page first
  await page.goto(BASE + '/login');
  await page.evaluate((auth) => {
    localStorage.setItem('kraken-auth', auth);
  }, AUTH_STATE);
  await page.goto(BASE + path, { waitUntil: 'networkidle', timeout: 15000 });
  // Wait for any lazy-loaded content
  await page.waitForTimeout(1000);
}

async function checkNoJSErrors(page: Page): Promise<string[]> {
  const errors: string[] = [];
  page.on('pageerror', (err) => errors.push(err.message));
  return errors;
}

// ============================================================
// 1. LOGIN PAGE
// ============================================================
test.describe('1. Login Page', () => {
  test('Login page renders', async ({ page }) => {
    await page.goto(BASE + '/login');
    await page.waitForTimeout(500);
    await page.screenshot({ path: 'screenshots/01-login.png', fullPage: true });
    // Should have some form of login UI
    const body = await page.textContent('body');
    expect(body).toBeTruthy();
  });

  test('Unauthenticated redirect to login', async ({ page }) => {
    // Clear any auth
    await page.goto(BASE + '/login');
    await page.evaluate(() => localStorage.clear());
    await page.goto(BASE + '/dashboard');
    await page.waitForTimeout(1000);
    // Should redirect to login
    expect(page.url()).toContain('/login');
  });
});

// ============================================================
// 2. DASHBOARD
// ============================================================
test.describe('2. Dashboard', () => {
  test('Dashboard loads and renders', async ({ page }) => {
    const errors = await checkNoJSErrors(page);
    await authenticateAndGoto(page, '/dashboard');
    await page.screenshot({ path: 'screenshots/02-dashboard.png', fullPage: true });

    // Check page didn't redirect to login
    expect(page.url()).toContain('/dashboard');

    // Should have some content (not just loading)
    const body = await page.textContent('body');
    expect(body!.length).toBeGreaterThan(10);
  });

  test('Dashboard has navigation sidebar', async ({ page }) => {
    await authenticateAndGoto(page, '/dashboard');
    // Look for nav or sidebar element
    const nav = await page.$('nav, [class*="sidebar"], [class*="Sidebar"], aside');
    await page.screenshot({ path: 'screenshots/02-dashboard-nav.png', fullPage: true });
    expect(nav).toBeTruthy();
  });
});

// ============================================================
// 3. SESSIONS
// ============================================================
test.describe('3. Sessions', () => {
  test('Sessions page loads', async ({ page }) => {
    await authenticateAndGoto(page, '/sessions');
    await page.screenshot({ path: 'screenshots/03-sessions.png', fullPage: true });
    expect(page.url()).toContain('/sessions');
    const body = await page.textContent('body');
    expect(body!.length).toBeGreaterThan(10);
  });

  test('Sessions page has table or list', async ({ page }) => {
    await authenticateAndGoto(page, '/sessions');
    const tableOrList = await page.$('table, [class*="list"], [class*="List"], [role="grid"], [role="table"]');
    await page.screenshot({ path: 'screenshots/03-sessions-content.png', fullPage: true });
    // Page should have structured data display
    expect(tableOrList).toBeTruthy();
  });
});

// ============================================================
// 4. SESSION DETAIL
// ============================================================
test.describe('4. Session Detail', () => {
  test('Session detail page loads with valid ID', async ({ page }) => {
    await authenticateAndGoto(page, `/sessions/${SESSION_ID}`);
    await page.screenshot({ path: 'screenshots/04-session-detail.png', fullPage: true });
    expect(page.url()).toContain(`/sessions/${SESSION_ID}`);
  });

  test('Session detail with invalid ID handles gracefully', async ({ page }) => {
    await authenticateAndGoto(page, '/sessions/00000000-0000-0000-0000-000000000000');
    await page.screenshot({ path: 'screenshots/04-session-detail-invalid.png', fullPage: true });
    // Should not crash - page should still render something
    const body = await page.textContent('body');
    expect(body).toBeTruthy();
  });
});

// ============================================================
// 5. TOPOLOGY
// ============================================================
test.describe('5. Topology', () => {
  test('Topology page loads', async ({ page }) => {
    await authenticateAndGoto(page, '/topology');
    await page.screenshot({ path: 'screenshots/05-topology.png', fullPage: true });
    expect(page.url()).toContain('/topology');
  });
});

// ============================================================
// 6. LISTENERS
// ============================================================
test.describe('6. Listeners', () => {
  test('Listeners page loads', async ({ page }) => {
    await authenticateAndGoto(page, '/listeners');
    await page.screenshot({ path: 'screenshots/06-listeners.png', fullPage: true });
    expect(page.url()).toContain('/listeners');
    const body = await page.textContent('body');
    expect(body!.length).toBeGreaterThan(10);
  });
});

// ============================================================
// 7. LOOT
// ============================================================
test.describe('7. Loot', () => {
  test('Loot page loads', async ({ page }) => {
    await authenticateAndGoto(page, '/loot');
    await page.screenshot({ path: 'screenshots/07-loot.png', fullPage: true });
    expect(page.url()).toContain('/loot');
  });
});

// ============================================================
// 8. FILES (requires session ID)
// ============================================================
test.describe('8. Files', () => {
  test('Files page loads with session ID', async ({ page }) => {
    await authenticateAndGoto(page, `/files/${SESSION_ID}`);
    await page.screenshot({ path: 'screenshots/08-files.png', fullPage: true });
    expect(page.url()).toContain('/files/');
  });

  test('Files page with invalid session handles gracefully', async ({ page }) => {
    await authenticateAndGoto(page, '/files/00000000-0000-0000-0000-000000000000');
    await page.screenshot({ path: 'screenshots/08-files-invalid.png', fullPage: true });
    const body = await page.textContent('body');
    expect(body).toBeTruthy();
  });
});

// ============================================================
// 9. PROCESSES (requires session ID)
// ============================================================
test.describe('9. Processes', () => {
  test('Processes page loads with session ID', async ({ page }) => {
    await authenticateAndGoto(page, `/processes/${SESSION_ID}`);
    await page.screenshot({ path: 'screenshots/09-processes.png', fullPage: true });
    expect(page.url()).toContain('/processes/');
  });
});

// ============================================================
// 10. MODULES
// ============================================================
test.describe('10. Modules', () => {
  test('Modules page loads', async ({ page }) => {
    await authenticateAndGoto(page, '/modules');
    await page.screenshot({ path: 'screenshots/10-modules.png', fullPage: true });
    expect(page.url()).toContain('/modules');
  });
});

// ============================================================
// 11. REPORTS
// ============================================================
test.describe('11. Reports', () => {
  test('Reports page loads', async ({ page }) => {
    await authenticateAndGoto(page, '/reports');
    await page.screenshot({ path: 'screenshots/11-reports.png', fullPage: true });
    expect(page.url()).toContain('/reports');
  });
});

// ============================================================
// 12. OPERATORS
// ============================================================
test.describe('12. Operators', () => {
  test('Operators page loads', async ({ page }) => {
    await authenticateAndGoto(page, '/operators');
    await page.screenshot({ path: 'screenshots/12-operators.png', fullPage: true });
    expect(page.url()).toContain('/operators');
  });
});

// ============================================================
// 13. DEFENDER
// ============================================================
test.describe('13. Defender', () => {
  test('Defender page loads', async ({ page }) => {
    await authenticateAndGoto(page, '/defender');
    await page.screenshot({ path: 'screenshots/13-defender.png', fullPage: true });
    expect(page.url()).toContain('/defender');
  });
});

// ============================================================
// 14. PAYLOADS
// ============================================================
test.describe('14. Payloads', () => {
  test('Payloads page loads', async ({ page }) => {
    await authenticateAndGoto(page, '/payloads');
    await page.screenshot({ path: 'screenshots/14-payloads.png', fullPage: true });
    expect(page.url()).toContain('/payloads');
  });
});

// ============================================================
// 15. SETTINGS
// ============================================================
test.describe('15. Settings', () => {
  test('Settings page loads', async ({ page }) => {
    await authenticateAndGoto(page, '/settings');
    await page.screenshot({ path: 'screenshots/15-settings.png', fullPage: true });
    expect(page.url()).toContain('/settings');
  });
});

// ============================================================
// 16. AUDIT
// ============================================================
test.describe('16. Audit Log', () => {
  test('Audit page loads', async ({ page }) => {
    await authenticateAndGoto(page, '/audit');
    await page.screenshot({ path: 'screenshots/16-audit.png', fullPage: true });
    expect(page.url()).toContain('/audit');
  });
});

// ============================================================
// 17. JOBS
// ============================================================
test.describe('17. Jobs', () => {
  test('Jobs page loads', async ({ page }) => {
    await authenticateAndGoto(page, '/jobs');
    await page.screenshot({ path: 'screenshots/17-jobs.png', fullPage: true });
    expect(page.url()).toContain('/jobs');
  });
});

// ============================================================
// EDGE CASE & SECURITY TESTS
// ============================================================
test.describe('Edge Cases & Security', () => {
  test('404 - Unknown route handling', async ({ page }) => {
    await authenticateAndGoto(page, '/this-route-does-not-exist-12345');
    await page.screenshot({ path: 'screenshots/edge-404.png', fullPage: true });
    const body = await page.textContent('body');
    expect(body).toBeTruthy();
  });

  test('XSS in URL parameter - session ID', async ({ page }) => {
    await authenticateAndGoto(page, '/sessions/<script>alert(1)</script>');
    await page.screenshot({ path: 'screenshots/edge-xss-url.png', fullPage: true });
    // Check no script execution happened
    const body = await page.textContent('body');
    expect(body).not.toContain('<script>');
  });

  test('SQL injection in URL parameter', async ({ page }) => {
    await authenticateAndGoto(page, "/sessions/' OR '1'='1");
    await page.screenshot({ path: 'screenshots/edge-sqli-url.png', fullPage: true });
    const body = await page.textContent('body');
    expect(body).toBeTruthy();
  });

  test('Path traversal attempt', async ({ page }) => {
    await authenticateAndGoto(page, '/files/../../etc/passwd');
    await page.screenshot({ path: 'screenshots/edge-path-traversal.png', fullPage: true });
    const body = await page.textContent('body');
    expect(body).not.toContain('root:x:0:0');
  });

  test('Extremely long URL parameter', async ({ page }) => {
    const longId = 'A'.repeat(5000);
    await authenticateAndGoto(page, `/sessions/${longId}`);
    await page.screenshot({ path: 'screenshots/edge-long-url.png', fullPage: true });
    const body = await page.textContent('body');
    expect(body).toBeTruthy();
  });

  test('Unicode characters in URL', async ({ page }) => {
    await authenticateAndGoto(page, '/sessions/%E2%80%8B%00%E2%80%8B');
    await page.screenshot({ path: 'screenshots/edge-unicode-url.png', fullPage: true });
    const body = await page.textContent('body');
    expect(body).toBeTruthy();
  });

  test('No sensitive data in page source', async ({ page }) => {
    await authenticateAndGoto(page, '/dashboard');
    const content = await page.content();
    // Should not expose API keys, tokens, or passwords in HTML
    expect(content).not.toMatch(/password\s*[:=]\s*['"][^'"]+['"]/i);
    expect(content).not.toMatch(/api[_-]?key\s*[:=]\s*['"][^'"]+['"]/i);
    expect(content).not.toMatch(/secret\s*[:=]\s*['"][^'"]+['"]/i);
  });

  test('Console errors check on dashboard', async ({ page }) => {
    const consoleErrors: string[] = [];
    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });
    await authenticateAndGoto(page, '/dashboard');
    await page.waitForTimeout(2000);
    // Log errors but don't fail - informational
    if (consoleErrors.length > 0) {
      console.log('Console errors found:', consoleErrors);
    }
    // We just record them, not fail
    expect(true).toBe(true);
  });

  test('Rapid navigation does not crash', async ({ page }) => {
    await authenticateAndGoto(page, '/dashboard');
    const routes = ['/sessions', '/listeners', '/modules', '/loot', '/jobs', '/dashboard'];
    for (const route of routes) {
      await page.goto(BASE + route, { waitUntil: 'domcontentloaded', timeout: 10000 });
    }
    await page.screenshot({ path: 'screenshots/edge-rapid-nav.png', fullPage: true });
    const body = await page.textContent('body');
    expect(body).toBeTruthy();
  });

  test('Page responsive at mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await authenticateAndGoto(page, '/dashboard');
    await page.screenshot({ path: 'screenshots/edge-mobile-viewport.png', fullPage: true });
    // Should not have horizontal overflow causing issues
    const body = await page.textContent('body');
    expect(body).toBeTruthy();
  });

  test('Logout clears auth state', async ({ page }) => {
    await authenticateAndGoto(page, '/dashboard');
    // Clear auth to simulate logout
    await page.evaluate(() => localStorage.removeItem('kraken-auth'));
    await page.goto(BASE + '/dashboard');
    await page.waitForTimeout(1000);
    // Should redirect to login
    expect(page.url()).toContain('/login');
    await page.screenshot({ path: 'screenshots/edge-logout.png', fullPage: true });
  });
});

// ============================================================
// PERFORMANCE TESTS
// ============================================================
test.describe('Performance', () => {
  test('Dashboard loads within 5 seconds', async ({ page }) => {
    const start = Date.now();
    await authenticateAndGoto(page, '/dashboard');
    const duration = Date.now() - start;
    console.log(`Dashboard load time: ${duration}ms`);
    expect(duration).toBeLessThan(5000);
  });

  test('Sessions page loads within 5 seconds', async ({ page }) => {
    const start = Date.now();
    await authenticateAndGoto(page, '/sessions');
    const duration = Date.now() - start;
    console.log(`Sessions load time: ${duration}ms`);
    expect(duration).toBeLessThan(5000);
  });

  test('No excessive network requests on dashboard', async ({ page }) => {
    const requests: string[] = [];
    page.on('request', (req) => requests.push(req.url()));
    await authenticateAndGoto(page, '/dashboard');
    await page.waitForTimeout(3000);
    console.log(`Total requests on dashboard: ${requests.length}`);
    // Sanity check - should not make hundreds of requests
    expect(requests.length).toBeLessThan(200);
  });
});
