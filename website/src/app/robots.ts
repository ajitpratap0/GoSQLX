import type { MetadataRoute } from 'next';

// Disallow only the Sentry tunnel (tunnelRoute in next.config.ts). Never block
// /wasm/ or other assets: the playground needs them and Googlebot must render it.
export default function robots(): MetadataRoute.Robots {
  return {
    rules: [{ userAgent: '*', allow: '/', disallow: ['/monitoring'] }],
    sitemap: 'https://gosqlx.dev/sitemap.xml',
    host: 'https://gosqlx.dev',
  };
}
