import { test as base } from '@playwright/test';

type ConsoleMonitor = {
  errors: string[];
  warnings: string[];
  assertNoErrors: (allowList?: string[]) => void;
};

export const test = base.extend<{ consoleMonitor: ConsoleMonitor }>({
  consoleMonitor: async ({ page }, use) => {
    const errors: string[] = [];
    const warnings: string[] = [];

    page.on('console', (msg) => {
      if (msg.type() === 'error') errors.push(msg.text());
      if (msg.type() === 'warning') warnings.push(msg.text());
    });

    page.on('pageerror', (err) => {
      errors.push(err.message);
    });

    const monitor = {
      errors,
      warnings,
      assertNoErrors: (allowList: string[] = []) => {
        const unexpected = errors.filter(
          err => !allowList.some(allowed => err.includes(allowed))
        );
        if (unexpected.length > 0) {
          throw new Error(`Unexpected console errors: ${unexpected.join(', ')}`);
        }
      }
    };

    await use(monitor);
  }
});

export { expect } from '@playwright/test';
