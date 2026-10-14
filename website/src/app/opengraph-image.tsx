import { renderOgCard } from '@/lib/og-image';
import { PROJECT } from '@/data/metrics';

export const alt = "Go SQL Parser, Formatter & Linter";
export const size = { width: 1200, height: 630 };
export const contentType = 'image/png';

export default function Image() {
  return renderOgCard({
    eyebrow: "SQL parsing SDK for Go",
    title: "Go SQL Parser, Formatter & Linter",
    subtitle: "Zero-copy, thread-safe, multi-dialect.",
    stat: `${PROJECT.dialectCount} dialects · ${PROJECT.lintRuleCount} lint rules · ${PROJECT.minGo}`,
  });
}
