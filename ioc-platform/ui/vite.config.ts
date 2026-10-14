import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv, type ProxyOptions } from "vite";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const port = Number(env.VITE_PORT || 5173);
  const proxyTarget = env.VITE_PROXY_TARGET || "http://localhost:8000";

  const apiProxy: ProxyOptions = {
    target: proxyTarget,
    changeOrigin: true,
  };

  const sseProxy: ProxyOptions = {
    target: proxyTarget,
    changeOrigin: true,
    configure: (proxy) => {
      proxy.on("proxyReq", (proxyReq) => {
        proxyReq.setHeader("Connection", "keep-alive");
      });
      proxy.on("proxyRes", (proxyRes) => {
        proxyRes.headers["Cache-Control"] = "no-cache";
        proxyRes.headers["Connection"] = "keep-alive";
        if (proxyRes.headers["content-type"]?.includes("text/event-stream")) {
          proxyRes.headers["X-Accel-Buffering"] = "no";
        }
      });
    },
  };

  return {
    plugins: [react(), tailwindcss()],
    server: {
      port,
      proxy: {
        "/api/tasks/": sseProxy,
        "/api/batch/": sseProxy,
        "/api": apiProxy,
      },
    },
  };
});
