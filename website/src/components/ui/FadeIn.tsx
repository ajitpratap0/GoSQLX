import type { CSSProperties, ReactNode } from 'react';

interface FadeInProps {
  children: ReactNode;
  delay?: number;
  className?: string;
  /** Kept for call-site compatibility; the reveal is always scroll-driven CSS. */
  viewport?: boolean;
}

/**
 * Server component. Content is always visible in the server HTML; the reveal is
 * a progressive enhancement defined in globals.css (scroll-driven animation).
 */
export function FadeIn({ children, delay = 0, className = '' }: FadeInProps) {
  const style = { '--reveal-delay': `${Math.min(delay, 0.2)}s` } as CSSProperties;
  return (
    <div className={`reveal ${className}`.trim()} style={style}>
      {children}
    </div>
  );
}
