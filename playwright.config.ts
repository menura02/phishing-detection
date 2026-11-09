import { defineConfig } from '@playwright/test';

const port = 4174;
const baseURL = 'http://127.0.0.1:' + port;

export default defineConfig({
  testDir: './tests',
  testMatch: '**/*.spec.ts',
  use: {
    baseURL,
    channel: process.env.PLAYWRIGHT_CHANNEL,
    trace: 'off',
  },
  webServer: {
    command: 'npm run preview -- --port ' + port,
    url: baseURL,
    reuseExistingServer: false,
  },
});
