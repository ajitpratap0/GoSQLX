import { Inter, JetBrains_Mono } from 'next/font/google';

// Two variable families only. Omitting `weight` makes next/font load the
// variable font file, so every weight is served from a single woff2.
export const inter = Inter({
  subsets: ['latin'],
  variable: '--font-inter',
  display: 'swap',
});

// Code, stat numbers and eyebrows. Not preloaded: it is not needed for the
// first paint of most routes.
export const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-jetbrains',
  display: 'swap',
  preload: false,
});
