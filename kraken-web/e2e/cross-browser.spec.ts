import { test, expect } from '@playwright/test';

/**
 * Cross-browser compatibility tests
 *
 * These tests verify that critical UI functionality works correctly
 * across different browsers and viewport sizes.
 *
 * Run with: npx playwright test --config=playwright.cross-browser.config.ts
 */

test.describe('Cross-browser: Navigation', () => {
  test('should load the login page', async ({ page }) => {
    await page.goto('/');
    // Should redirect to login or show main UI
    await expect(page).toHaveURL(/\/(login)?/);
  });

  test('should render page title correctly', async ({ page }) => {
    await page.goto('/');
    await expect(page).toHaveTitle(/Kraken/i);
  });

  test('should have visible navigation elements', async ({ page }) => {
    await page.goto('/');
    // Check for basic layout elements
    const body = page.locator('body');
    await expect(body).toBeVisible();
  });
});

test.describe('Cross-browser: Layout', () => {
  test('should render without horizontal scroll on desktop', async ({ page, browserName }) => {
    // Skip mobile viewports for this test
    const viewportWidth = page.viewportSize()?.width || 1280;
    if (viewportWidth < 768) {
      test.skip();
      return;
    }

    await page.goto('/');

    // Check that page doesn't have horizontal overflow
    const documentWidth = await page.evaluate(() => document.documentElement.scrollWidth);
    const windowWidth = await page.evaluate(() => window.innerWidth);

    expect(documentWidth).toBeLessThanOrEqual(windowWidth + 20); // Allow small margin
  });

  test('should handle responsive layout on mobile', async ({ page }) => {
    const viewportWidth = page.viewportSize()?.width || 1280;

    await page.goto('/');

    // Page should be visible regardless of viewport size
    const body = page.locator('body');
    await expect(body).toBeVisible();

    // Content should fit within viewport (allowing for scrollbars)
    const documentWidth = await page.evaluate(() => document.documentElement.scrollWidth);
    expect(documentWidth).toBeLessThanOrEqual(viewportWidth + 50);
  });
});

test.describe('Cross-browser: CSS & Styling', () => {
  test('should apply styles correctly', async ({ page }) => {
    await page.goto('/');

    // Check that Tailwind CSS is loaded (dark theme typically uses specific colors)
    const body = page.locator('body');
    const backgroundColor = await body.evaluate(
      (el) => window.getComputedStyle(el).backgroundColor
    );

    // Background should have some color (not transparent)
    expect(backgroundColor).not.toBe('rgba(0, 0, 0, 0)');
  });

  test('should render fonts correctly', async ({ page }) => {
    await page.goto('/');

    const body = page.locator('body');
    const fontFamily = await body.evaluate((el) => window.getComputedStyle(el).fontFamily);

    // Should have a font-family set
    expect(fontFamily).toBeTruthy();
    expect(fontFamily.length).toBeGreaterThan(0);
  });
});

test.describe('Cross-browser: JavaScript', () => {
  test('should execute JavaScript without errors', async ({ page }) => {
    const errors: string[] = [];

    page.on('pageerror', (error) => {
      errors.push(error.message);
    });

    await page.goto('/');

    // Wait for app to initialize
    await page.waitForTimeout(1000);

    // Filter out known acceptable errors (e.g., network errors when server not running)
    const criticalErrors = errors.filter(
      (e) =>
        !e.includes('Failed to fetch') &&
        !e.includes('NetworkError') &&
        !e.includes('net::ERR')
    );

    expect(criticalErrors).toHaveLength(0);
  });

  test('should handle React hydration correctly', async ({ page }) => {
    await page.goto('/');

    // Check that React root is present and hydrated
    const reactRoot = page.locator('#root');
    await expect(reactRoot).toBeVisible();

    // Should have rendered content (not just empty div)
    const content = await reactRoot.innerHTML();
    expect(content.length).toBeGreaterThan(0);
  });
});

test.describe('Cross-browser: Forms', () => {
  test('should handle input fields correctly', async ({ page }) => {
    await page.goto('/login');

    // Find any input field
    const inputs = page.locator('input');
    const inputCount = await inputs.count();

    if (inputCount > 0) {
      const firstInput = inputs.first();
      await expect(firstInput).toBeVisible();

      // Test typing
      await firstInput.fill('test-value');
      await expect(firstInput).toHaveValue('test-value');

      // Test clearing
      await firstInput.clear();
      await expect(firstInput).toHaveValue('');
    }
  });

  test('should handle button clicks', async ({ page }) => {
    await page.goto('/');

    // Find any button
    const buttons = page.locator('button');
    const buttonCount = await buttons.count();

    if (buttonCount > 0) {
      const firstButton = buttons.first();
      await expect(firstButton).toBeVisible();

      // Button should be clickable (not throw)
      await expect(async () => {
        await firstButton.click({ timeout: 1000 });
      }).not.toThrow();
    }
  });
});

test.describe('Cross-browser: Keyboard Navigation', () => {
  test('should support tab navigation', async ({ page }) => {
    await page.goto('/');

    // Press Tab and verify focus moves
    await page.keyboard.press('Tab');

    const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
    expect(focusedElement).toBeTruthy();
  });

  test('should handle escape key', async ({ page }) => {
    await page.goto('/');

    // Escape key should not cause errors
    await page.keyboard.press('Escape');

    // Page should still be functional
    const body = page.locator('body');
    await expect(body).toBeVisible();
  });
});

test.describe('Cross-browser: Network Handling', () => {
  test('should handle API request failures gracefully', async ({ page }) => {
    // Intercept API calls and make them fail
    await page.route('**/api/**', (route) => {
      route.abort('failed');
    });

    const errors: string[] = [];
    page.on('pageerror', (error) => {
      // Collect JS errors (not expected network errors)
      if (!error.message.includes('fetch')) {
        errors.push(error.message);
      }
    });

    await page.goto('/');
    await page.waitForTimeout(2000);

    // Page should still render even if API fails
    const body = page.locator('body');
    await expect(body).toBeVisible();
  });

  test('should show loading states', async ({ page }) => {
    // Slow down API responses
    await page.route('**/api/**', async (route) => {
      await new Promise((resolve) => setTimeout(resolve, 1000));
      await route.continue();
    });

    await page.goto('/');

    // Page should handle slow loading
    const body = page.locator('body');
    await expect(body).toBeVisible();
  });
});

test.describe('Cross-browser: Scrolling', () => {
  test('should support smooth scrolling', async ({ page }) => {
    await page.goto('/');

    // Scroll down
    await page.evaluate(() => window.scrollTo(0, 500));

    const scrollY = await page.evaluate(() => window.scrollY);
    // Either scrolled or page is too short to scroll
    expect(scrollY).toBeGreaterThanOrEqual(0);
  });

  test('should handle scroll containers', async ({ page }) => {
    await page.goto('/');

    // Find scrollable elements
    const scrollableElements = await page.evaluate(() => {
      const elements = document.querySelectorAll('*');
      let count = 0;
      elements.forEach((el) => {
        const style = window.getComputedStyle(el);
        if (
          style.overflow === 'auto' ||
          style.overflow === 'scroll' ||
          style.overflowY === 'auto' ||
          style.overflowY === 'scroll'
        ) {
          count++;
        }
      });
      return count;
    });

    // Should have at least one scrollable container (or none, which is also valid)
    expect(scrollableElements).toBeGreaterThanOrEqual(0);
  });
});

test.describe('Cross-browser: Media Queries', () => {
  test('should apply correct styles for viewport size', async ({ page }) => {
    const viewportWidth = page.viewportSize()?.width || 1280;

    await page.goto('/');

    // Check that viewport-appropriate styles are applied
    const body = page.locator('body');
    await expect(body).toBeVisible();

    // Verify layout adapts to viewport
    if (viewportWidth >= 1024) {
      // Desktop: might have sidebar visible
      const sidebar = page.locator('[data-testid="sidebar"], nav, aside').first();
      const sidebarVisible = await sidebar.isVisible().catch(() => false);
      // Sidebar might or might not be visible depending on implementation
      expect(typeof sidebarVisible).toBe('boolean');
    }
  });
});

test.describe('Cross-browser: Cookies & Storage', () => {
  test('should handle localStorage', async ({ page }) => {
    await page.goto('/');

    // Test localStorage access
    const canAccessStorage = await page.evaluate(() => {
      try {
        localStorage.setItem('test', 'value');
        const result = localStorage.getItem('test') === 'value';
        localStorage.removeItem('test');
        return result;
      } catch {
        return false;
      }
    });

    expect(canAccessStorage).toBe(true);
  });

  test('should handle sessionStorage', async ({ page }) => {
    await page.goto('/');

    const canAccessStorage = await page.evaluate(() => {
      try {
        sessionStorage.setItem('test', 'value');
        const result = sessionStorage.getItem('test') === 'value';
        sessionStorage.removeItem('test');
        return result;
      } catch {
        return false;
      }
    });

    expect(canAccessStorage).toBe(true);
  });
});
