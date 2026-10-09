import path from 'path'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const backendPort = process.env.SAFEHARNESS_DEMO_BACKEND_PORT || '3001'

export default defineConfig({
  plugins: [react()],
  envDir: false,
  build: {
    rollupOptions: {
      output: {
        // Keep in sync with vite.config.ts — split vendors from app code.
        manualChunks(id: string) {
          if (!id.includes('node_modules')) return undefined
          const rel = id.split('node_modules/')[1]
          const parts = rel.split('/')
          const pkg = parts[0].startsWith('@') ? `${parts[0]}/${parts[1]}` : parts[0]
          if (pkg === 'react' || pkg === 'react-dom' || pkg === 'scheduler' || pkg === 'react-router' || pkg === 'react-router-dom') return 'react'
          if (pkg === 'antd' || pkg.startsWith('@ant-design') || pkg.startsWith('rc-')) return 'antd'
          if (pkg === 'motion' || pkg === 'framer-motion') return 'motion'
          if (pkg === 'echarts' || pkg === 'zrender') return 'echarts'
          // NOTE: no manual group for mermaid — it is dynamically imported;
          // grouping it here would hoist ~3MB into the eager preload set.
          if (pkg === 'moment' || pkg === 'dayjs') return 'date'
          // Keep in sync with vite.config.ts — default chunking for the rest.
          return undefined
        },
      },
    },
  },
  server: {
    host: '127.0.0.1',
    port: 3002,
    strictPort: true,
    proxy: {
      '/api': {
        target: `http://127.0.0.1:${backendPort}`,
        changeOrigin: true,
        rewrite: (requestPath) => requestPath.replace(/^\/api/, ''),
      },
      '/mock-sso': {
        target: `http://127.0.0.1:${backendPort}`,
        changeOrigin: true,
      },
      '/login': {
        target: `http://127.0.0.1:${backendPort}`,
        changeOrigin: true,
      },
      '/register': {
        target: `http://127.0.0.1:${backendPort}`,
        changeOrigin: true,
      },
    },
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
})
