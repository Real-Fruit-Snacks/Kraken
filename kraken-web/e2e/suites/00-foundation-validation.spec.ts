import { test, expect } from '../fixtures/auth.fixture';
import { test as consoleTest } from '../fixtures/console-monitor.fixture';
import { test as mockTest } from '../fixtures/mock-grpc.fixture';
import { TEST_TOKEN } from '../fixtures/test-data';

test.describe('Foundation Validation', () => {
  test('auth fixture injects localStorage', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/login');
    const storage = await authenticatedPage.evaluate(() =>
      localStorage.getItem('kraken-auth')
    );
    expect(storage).toBeTruthy();
    expect(storage).toContain(TEST_TOKEN);
  });

  consoleTest('console monitor captures errors', async ({ page, consoleMonitor }) => {
    await page.goto('/login');
    await page.evaluate(() => console.error('test error'));
    expect(consoleMonitor.errors).toContain('test error');
  });

  mockTest('mock-grpc intercepts requests', async ({ page, mockGrpc }) => {
    await mockGrpc.mockSessions([]);
    await page.goto('/dashboard');
    // If mock works, page won't get real backend errors
    await page.waitForLoadState('networkidle');
    expect(page.url()).toContain('/dashboard');
  });
});
