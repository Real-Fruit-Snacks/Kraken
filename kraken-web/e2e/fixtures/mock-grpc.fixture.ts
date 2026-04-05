import { test as base } from '@playwright/test';
import { TEST_SESSION_HEX, AUTH_STORAGE_KEY, AUTH_STORAGE } from './test-data';

type MockGrpc = {
  mockSessions: (sessions?: any[]) => Promise<void>;
  mockEmpty: () => Promise<void>;
  mockListeners: (listeners?: any[]) => Promise<void>;
  mockRoute: (service: string, method: string, body: Record<string, unknown>) => Promise<void>;
};

const defaultSession = {
  id: TEST_SESSION_HEX,
  hostname: 'test-host',
  username: 'test-user',
  os: 'Linux',
  arch: 'x86_64',
  internalIp: '192.168.1.100',
  externalIp: '10.0.0.1',
  pid: 1234,
  lastSeen: new Date().toISOString(),
};

export const test = base.extend<{ mockGrpc: MockGrpc }>({
  mockGrpc: async ({ page }, use) => {
    // Pre-authenticate so pages load in an authed state
    await page.addInitScript((storage) => {
      localStorage.setItem(storage.key, JSON.stringify(storage.value));
    }, { key: AUTH_STORAGE_KEY, value: AUTH_STORAGE });

    const mock: MockGrpc = {
      mockSessions: async (sessions = [defaultSession]) => {
        await page.route('**/kraken.ImplantService/ListImplants', (route) => {
          route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ implants: sessions }),
          });
        });
      },

      mockListeners: async (listeners = []) => {
        await page.route('**/kraken.ListenerService/ListListeners', (route) => {
          route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ listeners }),
          });
        });
      },

      mockRoute: async (service: string, method: string, body: Record<string, unknown>) => {
        await page.route(`**/kraken.${service}/${method}`, (route) => {
          route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(body),
          });
        });
      },

      mockEmpty: async () => {
        await page.route('**/kraken.*/**', (route) => {
          route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({}),
          });
        });
      },
    };

    // Default: mock all gRPC routes with empty responses
    await mock.mockEmpty();

    await use(mock);
  },
});

export { expect } from '@playwright/test';
