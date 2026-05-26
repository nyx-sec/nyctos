import path from "node:path";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Vite config mirrors nyx OSS: SPA build to `dist/`, dev proxy that
// forwards `/api/...` and the `/api/v1/events` websocket to the local
// nyx-agent daemon. The daemon listens on 127.0.0.1:8765 by default
// (see `[ui].listen_addr` in `Config::default`).
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8766",
        changeOrigin: false,
        ws: true,
      },
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: true,
    target: "es2022",
  },
});
