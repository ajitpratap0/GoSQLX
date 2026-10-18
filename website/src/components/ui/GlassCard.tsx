'use client';
import { m } from 'motion/react';
import { ReactNode } from 'react';

// No whileTap: Motion adds tabindex=0 to tappable non-interactive elements,
// which made every card a keyboard tab stop.
const spring = { type: 'spring' as const, stiffness: 400, damping: 17 };

export function GlassCard({ children, className = '', hover = true }: { children: ReactNode; className?: string; hover?: boolean }) {
  return (
    <m.div
      className={`glass ${hover ? 'glass-hover transition-colors duration-300' : ''} relative overflow-hidden ${className}`}
      whileHover={hover ? { scale: 1.02, y: -2 } : undefined}
      transition={spring}
    >
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-fg/10 to-transparent" />
      {children}
    </m.div>
  );
}
