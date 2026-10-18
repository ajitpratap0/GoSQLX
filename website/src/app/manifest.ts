import type { MetadataRoute } from 'next';

// Served at /manifest.webmanifest and linked from every page head by Next.js.
// Colours mirror --bg in globals.css (dark is the default theme).
export default function manifest(): MetadataRoute.Manifest {
  return {
    name: 'GoSQLX',
    short_name: 'GoSQLX',
    description: 'High-performance, zero-copy SQL parser, formatter and linter for Go.',
    start_url: '/',
    scope: '/',
    display: 'standalone',
    background_color: '#0A0A0F',
    theme_color: '#0A0A0F',
    icons: [
      { src: '/icons/icon-192.png', sizes: '192x192', type: 'image/png' },
      { src: '/icons/icon-512.png', sizes: '512x512', type: 'image/png' },
    ],
  };
}
