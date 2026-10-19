import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// `base: './'` makes the production build loadable from file:// inside Electron.
export default defineConfig({
  base: './',
  plugins: [react()],
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
  },
});
