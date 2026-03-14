import { defineConfig } from 'astro/config';
import react from '@astrojs/react';
import tailwind from '@astrojs/tailwind';

export default defineConfig({
  site: 'https://ajitpratap0.github.io',
  base: '/GoSQLX/',
  integrations: [react(), tailwind()],
  output: 'static',
});
