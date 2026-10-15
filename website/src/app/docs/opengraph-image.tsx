import { renderOgCard } from '@/lib/og-image';

export const alt = "GoSQLX Documentation";
export const size = { width: 1200, height: 630 };
export const contentType = 'image/png';

export default function Image() {
  return renderOgCard({
    eyebrow: "Documentation",
    title: "GoSQLX Documentation",
    subtitle: "Guides, API reference and tutorials.",
  });
}
