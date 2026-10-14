import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api/malware': 'http://127.0.0.1:5000',
      '/api/ioc': 'http://127.0.0.1:8000',
      '/api/events': 'http://127.0.0.1:5001',
      '/api/phishing': 'http://127.0.0.1:5002',
      '/api/ruleforge': 'http://127.0.0.1:8765',
    },
  },
});
