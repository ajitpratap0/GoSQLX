import { renderOgCard } from '@/lib/og-image';

export const alt = "Try GoSQLX in your browser";
export const size = { width: 1200, height: 630 };
export const contentType = 'image/png';

export default function Image() {
  return renderOgCard({
    eyebrow: "Playground",
    title: "Try GoSQLX in your browser",
    subtitle: "WASM-powered SQL parser, formatter and linter.",
  });
}
