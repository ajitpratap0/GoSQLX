import { renderOgCard } from '@/lib/og-image';

export const alt = "SQL diagnostics, formatting & linting";
export const size = { width: 1200, height: 630 };
export const contentType = 'image/png';

export default function Image() {
  return renderOgCard({
    eyebrow: "VS Code extension",
    title: "SQL diagnostics, formatting & linting",
    subtitle: "Powered by the GoSQLX language server.",
  });
}
