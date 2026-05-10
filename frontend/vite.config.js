import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 4173,
    proxy: {
      "/api": "http://localhost:8080"
    }
  },
  build: {
    outDir: "../src/main/resources/static",
    emptyOutDir: false,
    assetsDir: "nebula-assets"
  }
});
