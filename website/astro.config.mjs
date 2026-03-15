import { defineConfig } from 'astro/config';
import react from '@astrojs/react';
import tailwind from '@astrojs/tailwind';
import sitemap from '@astrojs/sitemap';
import { remarkFixLinks } from './src/plugins/remark-fix-links.mjs';

export default defineConfig({
  site: 'https://gosqlx.dev',
  integrations: [react(), tailwind(), sitemap()],
  output: 'static',
  markdown: {
    remarkPlugins: [remarkFixLinks],
  },
});
