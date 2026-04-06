import { test, expect } from '../fixtures/auth.fixture';
import { TEST_SESSION_HEX } from '../fixtures/test-data';

// Navigate directly to the session detail page using a known test session ID.
// Each test clicks a tab button and verifies the panel renders the expected UI.
// No backend calls are made — we only assert that elements are present in the DOM.
test.describe('Session Detail - New Tabs', () => {
  test.beforeEach(async ({ authenticatedPage }) => {
    await authenticatedPage.goto(`/sessions/${TEST_SESSION_HEX}`);
    // Wait for the detail page shell (Terminal tab is always first)
    await authenticatedPage.waitForSelector('button:has-text("Terminal")', { timeout: 10000 });
  });

  // ── 1. Keylog ───────────────────────────────────────────────────────────────
  test('Keylog tab renders with start/stop/dump controls', async ({ authenticatedPage }) => {
    await authenticatedPage.click('button:has-text("Keylog")');
    await expect(authenticatedPage.locator('h3:has-text("Keylogger")')).toBeVisible();
    // Toggle button shows "Start" initially (isRunning = false)
    await expect(
      authenticatedPage.locator('button:has-text("Start"), button:has-text("Stop")').first()
    ).toBeVisible();
    await expect(authenticatedPage.locator('button:has-text("Dump")')).toBeVisible();
  });

  // ── 2. Clipboard ────────────────────────────────────────────────────────────
  test('Clipboard tab renders with get/set/monitor controls', async ({ authenticatedPage }) => {
    await authenticatedPage.click('button:has-text("Clipboard")');
    await expect(authenticatedPage.locator('h3:has-text("Clipboard")')).toBeVisible();
    await expect(authenticatedPage.locator('button:has-text("Get")')).toBeVisible();
    await expect(authenticatedPage.locator('button:has-text("Set")')).toBeVisible();
    // Monitor toggle shows "Start Monitor" or "Stop Monitor"
    await expect(
      authenticatedPage.locator('button:has-text("Monitor")').first()
    ).toBeVisible();
  });

  // ── 3. Env ──────────────────────────────────────────────────────────────────
  test('Env tab renders with sysinfo/netinfo/envvars/whoami sub-tabs and fetch button', async ({ authenticatedPage }) => {
    await authenticatedPage.click('button:has-text("Env")');
    await expect(authenticatedPage.locator('h3:has-text("Environment")')).toBeVisible();
    await expect(authenticatedPage.locator('button:has-text("System Info")')).toBeVisible();
    await expect(authenticatedPage.locator('button:has-text("Network Info")')).toBeVisible();
    await expect(authenticatedPage.locator('button:has-text("Env Vars")')).toBeVisible();
    await expect(authenticatedPage.locator('button:has-text("Whoami")')).toBeVisible();
    await expect(authenticatedPage.locator('button:has-text("Fetch")')).toBeVisible();
  });

  // ── 4. Registry ─────────────────────────────────────────────────────────────
  test('Registry tab renders with path input and enumerate button', async ({ authenticatedPage }) => {
    await authenticatedPage.click('button:has-text("Registry")');
    await expect(authenticatedPage.locator('h3:has-text("Registry Browser")')).toBeVisible();
    await expect(authenticatedPage.locator('input[placeholder="HKLM\\\\SOFTWARE"]')).toBeVisible();
    await expect(authenticatedPage.locator('button:has-text("Enumerate")')).toBeVisible();
  });

  // ── 5. Services ─────────────────────────────────────────────────────────────
  test('Services tab renders with list button', async ({ authenticatedPage }) => {
    await authenticatedPage.click('button:has-text("Services")');
    await expect(authenticatedPage.locator('h3:has-text("Service Manager")')).toBeVisible();
    await expect(authenticatedPage.locator('button:has-text("List Services")')).toBeVisible();
  });

  // ── 6. Persist ──────────────────────────────────────────────────────────────
  test('Persist tab renders with method dropdown and install button', async ({ authenticatedPage }) => {
    await authenticatedPage.click('button:has-text("Persist")');
    await expect(authenticatedPage.locator('h3:has-text("Persistence")')).toBeVisible();
    await expect(authenticatedPage.locator('select')).toBeVisible();
    await expect(authenticatedPage.locator('button:has-text("Install")')).toBeVisible();
  });

  // ── 7. Scan ─────────────────────────────────────────────────────────────────
  test('Scan tab renders with mode selector and target input', async ({ authenticatedPage }) => {
    await authenticatedPage.click('button:has-text("Scan")');
    await expect(authenticatedPage.locator('h3:has-text("Network Scan")')).toBeVisible();
    await expect(authenticatedPage.locator('button:has-text("portscan")')).toBeVisible();
    await expect(authenticatedPage.locator('button:has-text("pingsweep")')).toBeVisible();
    await expect(authenticatedPage.locator('button:has-text("shareenum")')).toBeVisible();
    // Default mode is portscan — target input is visible
    await expect(authenticatedPage.locator('input[placeholder="192.168.1.1"]')).toBeVisible();
  });

  // ── 8. Lateral ──────────────────────────────────────────────────────────────
  test('Lateral tab renders with method selector, target input, and OPSEC badge', async ({ authenticatedPage }) => {
    await authenticatedPage.click('button:has-text("Lateral")');
    await expect(authenticatedPage.locator('h3:has-text("Lateral Movement")')).toBeVisible();
    await expect(authenticatedPage.locator('button:has-text("wmi")')).toBeVisible();
    await expect(authenticatedPage.locator('button:has-text("psexec")')).toBeVisible();
    await expect(
      authenticatedPage.locator('input[placeholder="192.168.1.10 or HOSTNAME"]')
    ).toBeVisible();
    await expect(authenticatedPage.locator('text=OPSEC Risk')).toBeVisible();
  });

  // ── 9. AD ───────────────────────────────────────────────────────────────────
  test('AD tab renders with enumerate buttons and LDAP query input', async ({ authenticatedPage }) => {
    await authenticatedPage.click('button:has-text("AD")');
    await expect(authenticatedPage.locator('h3:has-text("Active Directory")')).toBeVisible();
    await expect(authenticatedPage.locator('button:has-text("Enumerate Users")')).toBeVisible();
    await expect(authenticatedPage.locator('button:has-text("Enumerate Groups")')).toBeVisible();
    await expect(authenticatedPage.locator('button:has-text("Enumerate Computers")')).toBeVisible();
    await expect(authenticatedPage.locator('input[placeholder="(objectClass=user)"]')).toBeVisible();
    await expect(authenticatedPage.locator('button:has-text("Run Query")')).toBeVisible();
  });

  // ── 10. Creds ───────────────────────────────────────────────────────────────
  test('Creds tab renders with dump buttons and OPSEC warning', async ({ authenticatedPage }) => {
    await authenticatedPage.click('button:has-text("Creds")');
    await expect(authenticatedPage.locator('h3:has-text("Credential Dump")')).toBeVisible();
    await expect(authenticatedPage.locator('button:has-text("Dump")').first()).toBeVisible();
    await expect(authenticatedPage.locator('text=Warning')).toBeVisible();
  });

  // ── 11. Browser ─────────────────────────────────────────────────────────────
  test('Browser tab renders with browser checkboxes and dump type selector', async ({ authenticatedPage }) => {
    await authenticatedPage.click('button:has-text("Browser")');
    await expect(authenticatedPage.locator('h3:has-text("Browser Data Dump")')).toBeVisible();
    await expect(authenticatedPage.locator('text=Chrome')).toBeVisible();
    await expect(authenticatedPage.locator('text=Edge')).toBeVisible();
    await expect(authenticatedPage.locator('text=Firefox')).toBeVisible();
    await expect(authenticatedPage.locator('button:has-text("Passwords")')).toBeVisible();
    await expect(authenticatedPage.locator('button:has-text("Cookies")')).toBeVisible();
  });

  // ── 12. Media ───────────────────────────────────────────────────────────────
  test('Media tab renders with audio, webcam, and screenshot sections', async ({ authenticatedPage }) => {
    await authenticatedPage.click('button:has-text("Media")');
    await expect(authenticatedPage.locator('h3:has-text("Media Capture")')).toBeVisible();
    await expect(authenticatedPage.locator('text=Audio Capture')).toBeVisible();
    await expect(authenticatedPage.locator('text=Webcam Capture')).toBeVisible();
    await expect(authenticatedPage.locator('button:has-text("Capture")').first()).toBeVisible();
  });

  // ── 13. USB ─────────────────────────────────────────────────────────────────
  test('USB tab renders with start/stop toggle', async ({ authenticatedPage }) => {
    await authenticatedPage.click('button:has-text("USB")');
    await expect(authenticatedPage.locator('h3:has-text("USB Monitor")')).toBeVisible();
    await expect(
      authenticatedPage.locator('button:has-text("Start"), button:has-text("Stop")').first()
    ).toBeVisible();
  });

  // ── 14. RDP ─────────────────────────────────────────────────────────────────
  test('RDP tab renders with session ID input and hijack button', async ({ authenticatedPage }) => {
    await authenticatedPage.click('button:has-text("RDP")');
    await expect(authenticatedPage.locator('h3:has-text("RDP Hijack")')).toBeVisible();
    await expect(authenticatedPage.locator('input[placeholder="e.g. 2"]')).toBeVisible();
    await expect(authenticatedPage.locator('button:has-text("Hijack Session")')).toBeVisible();
  });

  // ── 15. NTLM ────────────────────────────────────────────────────────────────
  test('NTLM tab renders with host/port form fields and start relay button', async ({ authenticatedPage }) => {
    await authenticatedPage.click('button:has-text("NTLM")');
    await expect(authenticatedPage.locator('h3:has-text("NTLM Relay")')).toBeVisible();
    await expect(authenticatedPage.locator('input[placeholder="0.0.0.0"]')).toBeVisible();
    await expect(authenticatedPage.locator('input[placeholder="192.168.1.100"]')).toBeVisible();
    await expect(authenticatedPage.locator('button:has-text("Start Relay")')).toBeVisible();
  });

  // ── 16. PortFwd ─────────────────────────────────────────────────────────────
  test('PortFwd tab renders with bind port input and forward address fields', async ({ authenticatedPage }) => {
    await authenticatedPage.click('button:has-text("PortFwd")');
    await expect(authenticatedPage.locator('h3:has-text("Port Forwarding")')).toBeVisible();
    await expect(authenticatedPage.locator('text=Add Tunnel')).toBeVisible();
    await expect(authenticatedPage.locator('text=Bind Port')).toBeVisible();
    await expect(authenticatedPage.locator('text=Forward Address')).toBeVisible();
  });
});
