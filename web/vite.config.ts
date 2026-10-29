import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Built files are served by the console API (same origin), so CSP 'self' and SameSite=Strict cookies just work.
// No dev server: run `npm run watch` and `shield console`.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: { outDir: "dist", emptyOutDir: true, sourcemap: false, modulePreload: { polyfill: false } },
});
