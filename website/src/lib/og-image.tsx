import { ImageResponse } from 'next/og';
import { PROJECT } from '@/data/metrics';

export const OG_SIZE = { width: 1200, height: 630 } as const;

interface OgCardInput {
  /** Small label above the title, e.g. "Documentation". */
  eyebrow: string;
  title: string;
  subtitle?: string;
  /** Optional stat line; figures must come from src/data/metrics.ts. */
  stat?: string;
}

function titleSize(title: string): number {
  if (title.length > 70) return 52;
  if (title.length > 40) return 64;
  return 76;
}

/** Render a branded 1200x630 Open Graph card. */
export function renderOgCard({ eyebrow, title, subtitle, stat }: OgCardInput): ImageResponse {
  return new ImageResponse(
    (
      <div
        style={{
          width: '100%',
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          padding: '64px 72px',
          background: 'linear-gradient(135deg, #0b1020 0%, #111a35 60%, #1b1447 100%)',
          color: '#f8fafc',
          fontFamily: 'sans-serif',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', fontSize: 40, fontWeight: 700, letterSpacing: -1 }}>GoSQLX</div>
          <div style={{ display: 'flex', fontSize: 26, color: '#94a3b8' }}>{PROJECT.version}</div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          <div
            style={{
              display: 'flex',
              fontSize: 28,
              color: '#818cf8',
              textTransform: 'uppercase',
              letterSpacing: 4,
              marginBottom: 20,
            }}
          >
            {eyebrow}
          </div>
          <div
            style={{
              display: 'flex',
              fontSize: titleSize(title),
              fontWeight: 700,
              lineHeight: 1.1,
              letterSpacing: -2,
            }}
          >
            {title}
          </div>
          {subtitle ? (
            <div style={{ display: 'flex', fontSize: 32, color: '#cbd5e1', marginTop: 24 }}>{subtitle}</div>
          ) : null}
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 26, color: '#94a3b8' }}>
          <div style={{ display: 'flex' }}>{stat ?? 'gosqlx.dev'}</div>
          {stat ? <div style={{ display: 'flex' }}>gosqlx.dev</div> : null}
        </div>
      </div>
    ),
    { ...OG_SIZE },
  );
}
