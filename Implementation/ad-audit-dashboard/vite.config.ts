import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath, URL } from 'node:url';

// The dashboard is served locally only. Audit output can contain sensitive
// infrastructure detail, so nothing here is intended for public deployment.
export default defineConfig({
  plugins: [react()],
  base: './',
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    // Proxy the API through the dev server so the browser sees one origin.
    // That removes CORS from the picture entirely and means the token is the
    // only thing standing between a page and the scan endpoint.
    proxy: {
      '/api': {
        target: `http://127.0.0.1:${process.env.AUDIT_API_PORT ?? 5174}`,
        changeOrigin: false,
      },
    },
  },
  preview: { host: '127.0.0.1', port: 4173, strictPort: true },
  build: { outDir: 'dist', sourcemap: false },
});
