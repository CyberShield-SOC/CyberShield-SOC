import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

const securityHeaders = {
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Permissions-Policy": "camera=(), geolocation=(), microphone=()",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
};

// Locally-trusted dev certificate (see frontend/.cert/README.md for the
// mkcert commands that generate these). Falls back to `true` -- Vite's
// built-in transient self-signed cert -- so a fresh checkout without the
// cert files still starts, just with the "Not secure" browser warning
// this setup is meant to avoid. Production builds never read this file:
// `vite build` / `vite preview --host` for real deployments run behind a
// real reverse-proxy TLS terminator, not this dev server config.
function loadDevHttpsCert() {
  const certDir = fileURLToPath(new URL("./.cert", import.meta.url));
  try {
    return {
      cert: readFileSync(`${certDir}/localhost.pem`),
      key: readFileSync(`${certDir}/localhost-key.pem`),
    };
  } catch {
    return true;
  }
}

const devHttps = loadDevHttpsCert();

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    sourcemap: false,
    target: "es2022",
  },
  server: {
    host: "127.0.0.1",
    https: devHttps,
    headers: securityHeaders,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:3000",
        changeOrigin: false,
      },
    },
  },
  preview: {
    host: "127.0.0.1",
    https: devHttps,
    headers: securityHeaders,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:3000",
        changeOrigin: false,
      },
    },
  },
});
