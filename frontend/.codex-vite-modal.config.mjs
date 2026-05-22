import path from "node:path";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

function json(res, status, body) {
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify(body));
}

function readJson(req) {
  return new Promise((resolve) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
    });
    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        resolve({});
      }
    });
  });
}

function mockNyctosApi() {
  return {
    name: "mock-nyctos-api",
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        const url = req.url?.split("?")[0] ?? "";
        if (!url.startsWith("/api/v1/")) return next();

        if (req.method === "GET" && url === "/api/v1/setup/status") {
          return json(res, 200, {
            complete: true,
            config_path: "mock",
            ai_runtime: "none",
            sandbox_backend: "process",
          });
        }
        if (req.method === "GET" && url === "/api/v1/projects") {
          return json(res, 200, []);
        }
        if (req.method === "POST" && url === "/api/v1/launch-target/test") {
          const body = await readJson(req);
          return json(res, 200, {
            ok: true,
            url: body.url,
            message: "Reachable in 8ms",
            status: 200,
            elapsed_ms: 8,
          });
        }
        if (req.method === "POST" && url === "/api/v1/projects") {
          const body = await readJson(req);
          return json(res, 200, {
            id: `proj-${body.name ?? "app"}`,
            name: body.name ?? "app",
            description: body.description ?? null,
            target_base_url: body.target_base_url ?? null,
            env_config_json: null,
            runtime_profile: body.runtime_profile ?? null,
            default_launch_profile: body.default_launch_profile ?? null,
            created_at: 1,
            updated_at: 1,
          });
        }

        return json(res, 404, { error: { message: "mock endpoint not found" } });
      });
    },
  };
}

export default defineConfig({
  plugins: [mockNyctosApi(), react()],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "src"),
    },
  },
  server: {
    port: 5174,
    strictPort: true,
  },
});
