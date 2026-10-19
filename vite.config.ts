import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// `base: './'` makes the production build loadable from file:// inside Electron.
export default defineConfig({
  base: './',
  plugins: [react()],
  // Single offline bundle for the desktop app; code-splitting brings no benefit from file://.
  build: { chunkSizeWarningLimit: 1500 },
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
  },
});
