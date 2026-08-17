import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    // The dashboard talks to the scanner API through this proxy, so the browser
    // only ever makes same-origin requests (SSE included).
    proxy: {
      '/api': {
        target: process.env.VITE_API_TARGET || 'http://127.0.0.1:4000',
        changeOrigin: true,
        // Server-Sent Events must not be buffered by the dev proxy.
        configure: (proxy) => {
          proxy.on('proxyRes', (proxyRes) => {
            if (String(proxyRes.headers['content-type']).includes('text/event-stream')) {
              proxyRes.headers['cache-control'] = 'no-cache, no-transform';
            }
          });
        },
      },
    },
  },
});
