import { defineConfig } from 'astro/config';
import tailwind from '@astrojs/tailwind';
import icon from 'astro-icon';

// Theme developers running `npm run dev` need their browser at :4321 to
// reach the Go backend at :8080 for the dynamic `/api/*` and `/healthz`
// surface. Without this proxy the dev frontend would hit
// http://localhost:4321/api/... and 404, which used to be the silent
// gotcha behind "I cloned the repo, ran npm run dev, and the page is
// empty". The override is `PULSE_API_BASE=http://1.2.3.4:8080 npm run
// dev` for working against a remote staging instance, or just leaving
// it unset to talk to a local `go run .`.
const apiBase = process.env.PULSE_API_BASE || 'http://localhost:8080';

export default defineConfig({
	integrations: [tailwind(), icon()],
	server: {
		host: true, // 监听所有网络接口
		port: 4321,
	},
	vite: {
		optimizeDeps: {
			// 强制重新优化依赖
			force: true,
		},
		server: {
			hmr: {
				// 允许通过 IP 访问时的 HMR
				clientPort: 4321,
			},
			// Dev-only proxy: forwards live API + SSE traffic to whatever
			// backend $PULSE_API_BASE points at. The `changeOrigin: true`
			// flag rewrites the Host header so the Go server sees the
			// request as if it had come in directly. `ws: true` is needed
			// for SSE event streams (and any future websocket endpoints).
			proxy: {
				'/api':     { target: apiBase, changeOrigin: true, ws: true },
				'/healthz': { target: apiBase, changeOrigin: true },
			},
		},
	},
});

