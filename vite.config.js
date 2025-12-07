// vite.config.js
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';
import tailwindcss from "@tailwindcss/vite";
export default defineConfig({
  plugins: [tailwindcss(), sveltekit()],
  css: { postcss: true },
  server: {
    host: true,
    port: 5173,
    allowedHosts: ['{{VIBE_DOMAIN}}'],
    hmr: false,
  },
  ssr: {
    noExternal: ["flowbite-svelte", "flowbite-svelte-icons"]
  }
});
