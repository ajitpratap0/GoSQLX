import { renderOgCard } from '@/lib/og-image';

export const alt = "GoSQLX Changelog";
export const size = { width: 1200, height: 630 };
export const contentType = 'image/png';

export default function Image() {
  return renderOgCard({
    eyebrow: "Changelog",
    title: "GoSQLX Changelog",
    subtitle: "Release notes for every version.",
  });
}
