import { renderOgCard } from '@/lib/og-image';

export const alt = "GoSQLX vs pg_query vs vitess-sqlparser";
export const size = { width: 1200, height: 630 };
export const contentType = 'image/png';

export default function Image() {
  return renderOgCard({
    eyebrow: "Comparison",
    title: "GoSQLX vs pg_query vs vitess-sqlparser",
    subtitle: "Go SQL parser comparison.",
  });
}
