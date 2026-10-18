import { renderOgCard } from '@/lib/og-image';

export const alt = 'GoSQLX Blog';
export const size = { width: 1200, height: 630 };
export const contentType = 'image/png';

export default function Image() {
  return renderOgCard({
    eyebrow: 'Blog',
    title: 'GoSQLX Blog',
    subtitle: 'Deep dives on parsing, linting and securing SQL in Go.',
  });
}
