import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  build: {
    // Не /assets/: это маршрут приложения (/assets/:assetId) — в проде nginx отдавал бы на него
    // файлы сборки, и перезагрузка карточки актива давала 404 (deploy/nginx.conf).
    assetsDir: 'static',
  },
  server: {
    // Тот же origin, что и в проде (deploy/nginx.conf: /api/ -> backend:8000):
    // браузер ходит на /api текущего адреса, без CORS и мимо системного прокси.
    proxy: {
      '/api': 'http://localhost:8000',
      '/health': 'http://localhost:8000',
    },
  },
})
