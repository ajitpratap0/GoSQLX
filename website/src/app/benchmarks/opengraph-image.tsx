import { renderOgCard } from '@/lib/og-image';
import { HEADLINE_CAPTION, HEADLINE_OPS_PER_SEC, formatOps } from '@/data/metrics';

export const alt = "Reproducible SQL parser numbers";
export const size = { width: 1200, height: 630 };
export const contentType = 'image/png';

export default function Image() {
  return renderOgCard({
    eyebrow: "Benchmarks",
    title: "Reproducible SQL parser numbers",
    subtitle: "Labelled by stage, hardware and Go version.",
    stat: `${formatOps(HEADLINE_OPS_PER_SEC)} ops/sec · ${HEADLINE_CAPTION}`,
  });
}
