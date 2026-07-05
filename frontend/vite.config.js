import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/upload': 'http://127.0.0.1:3000',
      '/api': 'http://127.0.0.1:3000',
    },
  },
});
