import { test as base } from '@playwright/test';
import { AUTH_STORAGE_KEY, AUTH_STORAGE } from './test-data';

export const test = base.extend({
  authenticatedPage: async ({ page }, use) => {
    await page.addInitScript((storage) => {
      localStorage.setItem(storage.key, JSON.stringify(storage.value));
    }, { key: AUTH_STORAGE_KEY, value: AUTH_STORAGE });
    await use(page);
  },

  unauthenticatedPage: async ({ page }, use) => {
    await page.addInitScript(() => {
      localStorage.clear();
    });
    await use(page);
  }
});

export { expect } from '@playwright/test';
