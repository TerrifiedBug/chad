import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  // Suite path prefix — keep in sync with BrowserRouter basename,
  // API_BASE/WS_BASE in src/lib/api.ts, and both nginx configs.
  base: '/chad/',
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 3000,
    proxy: {
      '/chad/api': {
        target: 'http://backend:8000',
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/chad\/api/, '/api'),
      },
      '/chad/ws': {
        target: 'ws://backend:8000',
        ws: true,
        rewrite: (p) => p.replace(/^\/chad\/ws/, '/ws'),
      },
    },
  },
})
