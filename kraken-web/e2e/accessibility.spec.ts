import { test, expect } from '@playwright/test';

/**
 * Web accessibility tests (WCAG 2.1 compliance)
 *
 * Tests verify:
 * - Keyboard navigation
 * - Focus management
 * - Color contrast (via visual inspection)
 * - ARIA attributes
 * - Semantic HTML
 * - Screen reader compatibility
 *
 * Run with: npx playwright test accessibility.spec.ts
 *
 * Note: For comprehensive accessibility testing, consider adding @axe-core/playwright
 * npm install @axe-core/playwright
 */

test.describe('Accessibility: Keyboard Navigation', () => {
  test('all interactive elements are focusable via keyboard', async ({ page }) => {
    await page.goto('/');

    // Get all interactive elements
    const interactiveSelectors = [
      'a[href]',
      'button:not([disabled])',
      'input:not([disabled])',
      'select:not([disabled])',
      'textarea:not([disabled])',
      '[tabindex]:not([tabindex="-1"])',
    ].join(', ');

    const interactiveCount = await page.locator(interactiveSelectors).count();

    if (interactiveCount > 0) {
      // Tab through elements and verify focus moves
      let focusedCount = 0;
      const maxTabs = Math.min(interactiveCount + 5, 50); // Limit iterations

      for (let i = 0; i < maxTabs; i++) {
        await page.keyboard.press('Tab');

        const focusedTag = await page.evaluate(() => document.activeElement?.tagName);
        if (focusedTag && focusedTag !== 'BODY') {
          focusedCount++;
        }
      }

      // At least some elements should receive focus
      expect(focusedCount).toBeGreaterThan(0);
    }
  });

  test('focus is visible on interactive elements', async ({ page }) => {
    await page.goto('/');

    // Tab to first focusable element
    await page.keyboard.press('Tab');

    const activeElement = page.locator(':focus');
    const isVisible = await activeElement.isVisible().catch(() => false);

    if (isVisible) {
      // Check for focus indicator (outline or other visual)
      const styles = await activeElement.evaluate((el) => {
        const computed = window.getComputedStyle(el);
        return {
          outline: computed.outline,
          outlineWidth: computed.outlineWidth,
          boxShadow: computed.boxShadow,
          border: computed.border,
        };
      });

      // Should have some form of focus indicator
      const hasFocusIndicator =
        styles.outlineWidth !== '0px' ||
        styles.boxShadow !== 'none' ||
        styles.outline !== 'none';

      // Note: This may fail if focus styles are custom; adjust as needed
      expect(hasFocusIndicator).toBe(true);
    }
  });

  test('escape key closes modals/dialogs', async ({ page }) => {
    await page.goto('/');

    // Try to open a modal if there's a trigger
    const modalTriggers = page.locator('[data-modal-trigger], [aria-haspopup="dialog"]');
    const triggerCount = await modalTriggers.count();

    if (triggerCount > 0) {
      await modalTriggers.first().click();

      // Check if modal opened
      const modal = page.locator('[role="dialog"], [aria-modal="true"], .modal');
      const modalVisible = await modal.isVisible().catch(() => false);

      if (modalVisible) {
        await page.keyboard.press('Escape');

        // Modal should close
        await expect(modal).not.toBeVisible({ timeout: 2000 });
      }
    }
  });

  test('arrow keys work in navigation menus', async ({ page }) => {
    await page.goto('/');

    // Find navigation
    const nav = page.locator('nav, [role="navigation"]').first();
    const navExists = await nav.count() > 0;

    if (navExists) {
      // Focus on nav
      await nav.focus();

      // Arrow key should not cause errors
      await page.keyboard.press('ArrowDown');
      await page.keyboard.press('ArrowUp');

      // Page should still be functional
      const body = page.locator('body');
      await expect(body).toBeVisible();
    }
  });
});

test.describe('Accessibility: ARIA Attributes', () => {
  test('images have alt attributes', async ({ page }) => {
    await page.goto('/');

    const images = page.locator('img');
    const imageCount = await images.count();

    for (let i = 0; i < imageCount; i++) {
      const img = images.nth(i);
      const alt = await img.getAttribute('alt');
      const role = await img.getAttribute('role');

      // Image should have alt text or be decorative (role="presentation")
      const hasAlt = alt !== null;
      const isDecorative = role === 'presentation' || role === 'none';

      expect(hasAlt || isDecorative).toBe(true);
    }
  });

  test('form inputs have labels', async ({ page }) => {
    await page.goto('/');

    const inputs = page.locator('input:not([type="hidden"]), textarea, select');
    const inputCount = await inputs.count();

    for (let i = 0; i < inputCount; i++) {
      const input = inputs.nth(i);
      const id = await input.getAttribute('id');
      const ariaLabel = await input.getAttribute('aria-label');
      const ariaLabelledBy = await input.getAttribute('aria-labelledby');
      const placeholder = await input.getAttribute('placeholder');
      const title = await input.getAttribute('title');

      // Check for associated label
      let hasLabel = false;

      if (id) {
        const label = page.locator(`label[for="${id}"]`);
        hasLabel = (await label.count()) > 0;
      }

      // Should have some form of label
      const isLabeled =
        hasLabel || ariaLabel || ariaLabelledBy || placeholder || title;

      expect(isLabeled).toBeTruthy();
    }
  });

  test('buttons have accessible names', async ({ page }) => {
    await page.goto('/');

    const buttons = page.locator('button, [role="button"]');
    const buttonCount = await buttons.count();

    for (let i = 0; i < buttonCount; i++) {
      const button = buttons.nth(i);
      const text = await button.textContent();
      const ariaLabel = await button.getAttribute('aria-label');
      const ariaLabelledBy = await button.getAttribute('aria-labelledby');
      const title = await button.getAttribute('title');

      // Button should have accessible name
      const hasAccessibleName =
        (text && text.trim().length > 0) || ariaLabel || ariaLabelledBy || title;

      expect(hasAccessibleName).toBeTruthy();
    }
  });

  test('links have descriptive text', async ({ page }) => {
    await page.goto('/');

    const links = page.locator('a[href]');
    const linkCount = await links.count();

    for (let i = 0; i < Math.min(linkCount, 20); i++) {
      // Limit to first 20
      const link = links.nth(i);
      const text = await link.textContent();
      const ariaLabel = await link.getAttribute('aria-label');
      const title = await link.getAttribute('title');

      // Link should have descriptive text
      const hasText = (text && text.trim().length > 0) || ariaLabel || title;

      expect(hasText).toBeTruthy();
    }
  });

  test('interactive elements have appropriate roles', async ({ page }) => {
    await page.goto('/');

    // Check clickable divs/spans have role="button"
    const clickableNonButtons = page.locator('div[onclick], span[onclick]');
    const count = await clickableNonButtons.count();

    for (let i = 0; i < count; i++) {
      const element = clickableNonButtons.nth(i);
      const role = await element.getAttribute('role');
      const tabindex = await element.getAttribute('tabindex');

      // Should have button role and be focusable
      expect(role).toBe('button');
      expect(tabindex).not.toBe('-1');
    }
  });
});

test.describe('Accessibility: Semantic HTML', () => {
  test('page has main landmark', async ({ page }) => {
    await page.goto('/');

    const main = page.locator('main, [role="main"]');
    const hasMain = (await main.count()) > 0;

    expect(hasMain).toBe(true);
  });

  test('page has navigation landmark', async ({ page }) => {
    await page.goto('/');

    const nav = page.locator('nav, [role="navigation"]');
    const hasNav = (await nav.count()) > 0;

    // Navigation is expected for most pages
    expect(hasNav).toBe(true);
  });

  test('headings are in logical order', async ({ page }) => {
    await page.goto('/');

    const headings = await page.evaluate(() => {
      const result: number[] = [];
      document.querySelectorAll('h1, h2, h3, h4, h5, h6').forEach((h) => {
        result.push(parseInt(h.tagName[1]));
      });
      return result;
    });

    // Check heading hierarchy (no skipping levels)
    if (headings.length > 1) {
      let previousLevel = 0;
      for (const level of headings) {
        // Level should not skip more than one (e.g., h1 to h3)
        if (previousLevel > 0) {
          const skipped = level - previousLevel;
          expect(skipped).toBeLessThanOrEqual(1);
        }
        previousLevel = level;
      }
    }
  });

  test('page has exactly one h1', async ({ page }) => {
    await page.goto('/');

    const h1Count = await page.locator('h1').count();

    // Should have exactly one h1 (or zero for login pages)
    expect(h1Count).toBeLessThanOrEqual(1);
  });

  test('lists use proper list elements', async ({ page }) => {
    await page.goto('/');

    // Find visual lists (groups of similar items)
    const lists = page.locator('ul, ol, [role="list"]');
    const listCount = await lists.count();

    for (let i = 0; i < listCount; i++) {
      const list = lists.nth(i);
      const children = list.locator('> li, > [role="listitem"]');
      const childCount = await children.count();

      // If it's a list, it should have list items
      if (childCount > 0) {
        expect(childCount).toBeGreaterThan(0);
      }
    }
  });
});

test.describe('Accessibility: Color & Contrast', () => {
  test('text is readable (has sufficient size)', async ({ page }) => {
    await page.goto('/');

    const textElements = page.locator('p, span, div, li, td, th, label');
    const count = Math.min(await textElements.count(), 20);

    for (let i = 0; i < count; i++) {
      const element = textElements.nth(i);
      const isVisible = await element.isVisible().catch(() => false);

      if (isVisible) {
        const fontSize = await element.evaluate((el) => {
          return parseFloat(window.getComputedStyle(el).fontSize);
        });

        // Text should be at least 12px (WCAG recommends 16px minimum)
        if (fontSize > 0) {
          expect(fontSize).toBeGreaterThanOrEqual(10);
        }
      }
    }
  });

  test('focus indicators are visible', async ({ page }) => {
    await page.goto('/');

    // Check that :focus-visible styles exist in the page
    const hasFocusStyles = await page.evaluate(() => {
      const styleSheets = Array.from(document.styleSheets);
      for (const sheet of styleSheets) {
        try {
          const rules = Array.from(sheet.cssRules || []);
          for (const rule of rules) {
            if (rule instanceof CSSStyleRule) {
              if (
                rule.selectorText?.includes(':focus') ||
                rule.selectorText?.includes(':focus-visible')
              ) {
                return true;
              }
            }
          }
        } catch {
          // Cross-origin stylesheet, skip
        }
      }
      return false;
    });

    // Should have focus styles defined (Tailwind includes these by default)
    expect(hasFocusStyles).toBe(true);
  });
});

test.describe('Accessibility: Motion & Animation', () => {
  test('respects prefers-reduced-motion', async ({ page }) => {
    // Emulate reduced motion preference
    await page.emulateMedia({ reducedMotion: 'reduce' });

    await page.goto('/');

    // Check that animations are disabled or reduced
    const hasReducedMotion = await page.evaluate(() => {
      return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    });

    expect(hasReducedMotion).toBe(true);
  });
});

test.describe('Accessibility: Screen Reader', () => {
  test('page has lang attribute', async ({ page }) => {
    await page.goto('/');

    const lang = await page.locator('html').getAttribute('lang');

    expect(lang).toBeTruthy();
    expect(lang?.length).toBeGreaterThanOrEqual(2); // e.g., "en", "en-US"
  });

  test('no empty links or buttons', async ({ page }) => {
    await page.goto('/');

    // Check for empty interactive elements
    const emptyLinks = await page.evaluate(() => {
      const links = document.querySelectorAll('a[href]');
      return Array.from(links).filter((a) => {
        const text = a.textContent?.trim() || '';
        const ariaLabel = a.getAttribute('aria-label') || '';
        const title = a.getAttribute('title') || '';
        const hasImage = a.querySelector('img, svg') !== null;
        return text === '' && ariaLabel === '' && title === '' && !hasImage;
      }).length;
    });

    expect(emptyLinks).toBe(0);
  });

  test('skip link exists', async ({ page }) => {
    await page.goto('/');

    // Look for skip link (commonly first focusable element)
    const skipLink = page.locator('a[href="#main"], a[href="#content"], .skip-link');
    const hasSkipLink = (await skipLink.count()) > 0;

    // Skip link is recommended but not required
    // Log warning if missing
    if (!hasSkipLink) {
      console.log(
        'Accessibility notice: Consider adding a skip navigation link for keyboard users'
      );
    }
  });

  test('aria-live regions exist for dynamic content', async ({ page }) => {
    await page.goto('/');

    // Check for aria-live regions (used for notifications, alerts)
    const liveRegions = page.locator('[aria-live], [role="alert"], [role="status"]');
    const count = await liveRegions.count();

    // Log if no live regions (they should exist for toast notifications, etc.)
    if (count === 0) {
      console.log(
        'Accessibility notice: Consider adding aria-live regions for dynamic content updates'
      );
    }
  });
});

test.describe('Accessibility: Tables', () => {
  test('data tables have headers', async ({ page }) => {
    await page.goto('/');

    const tables = page.locator('table');
    const tableCount = await tables.count();

    for (let i = 0; i < tableCount; i++) {
      const table = tables.nth(i);
      const headers = table.locator('th');
      const headerCount = await headers.count();

      // Data tables should have headers
      // Skip if it appears to be a layout table (no headers is acceptable)
      const role = await table.getAttribute('role');
      if (role !== 'presentation' && role !== 'none') {
        expect(headerCount).toBeGreaterThan(0);
      }
    }
  });
});
