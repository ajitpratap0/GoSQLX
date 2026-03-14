import { defineConfig } from 'astro/config';
import react from '@astrojs/react';
import tailwind from '@astrojs/tailwind';
import { remarkFixLinks } from './src/plugins/remark-fix-links.mjs';

export default defineConfig({
  site: 'https://ajitpratap0.github.io',
  base: '/GoSQLX/',
  integrations: [react(), tailwind()],
  output: 'static',
  markdown: {
    remarkPlugins: [remarkFixLinks],
  },
});
