import { defineConfig } from 'vitest/config';
import path from 'node:path';

export default defineConfig({
  resolve: {
    alias: { '@': path.resolve(__dirname, 'src') },
  },
  test: {
    // src only. The API server beside this project has its own suite, written
    // against node:test and run with `npm test` in server/, because it starts
    // the real server as a child process rather than importing it.
    include: ['src/**/*.test.ts'],
    environment: 'node',
  },
});
