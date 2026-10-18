/** Canonical origin of the production site. */
export const SITE_URL = 'https://gosqlx.dev';

/** Browser-chrome colours. Keep in sync with --bg in globals.css (dark and html.light). */
export const THEME_COLORS = { dark: '#0A0A0F', light: '#FAFBFC' } as const;

/** RSS autodiscovery feeds advertised in every page head. */
export const RSS_FEEDS = [
  { url: '/changelog/feed.xml', title: 'GoSQLX Release Notes' },
  { url: '/blog/rss.xml', title: 'GoSQLX Blog' },
];
