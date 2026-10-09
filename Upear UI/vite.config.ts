import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const repoRoot = path.resolve(__dirname, '..')
  const env = loadEnv(mode, repoRoot, '')
  const backendPort = env.BACKEND_PORT || env.PORT || '3001'
  const frontendPort = Number(env.FRONTEND_PORT || '3002')
  const proxyTarget = `http://localhost:${backendPort}`

  return {
    plugins: [react()],
    // 从项目根目录读取 .env，使 VITE_API_BASE_URL 和 SSO_LOGIN_URL 在 build 时生效
    envDir: repoRoot,
    envPrefix: ['VITE_', 'SSO_LOGIN_URL'],
    build: {
      rollupOptions: {
        output: {
          // Split heavy vendor packages out of the entry chunk so browser
          // caching and parallel downloads work; app code stays separate.
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
            // Everything else keeps Rollup's default chunking so existing
            // dynamic-import splits (xlsx, docx, katex, locales, …) survive.
            return undefined
          },
        },
      },
    },
    server: {
      host: '0.0.0.0',
      port: frontendPort,
      strictPort: true,
      proxy: {
        '/api': {
          target: proxyTarget,
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api/, ''),
        },
        '/mock-sso': {
          target: proxyTarget,
          changeOrigin: true,
        },
      },
    },
  }
})
