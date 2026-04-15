'use client';

import { useRef, useCallback, ReactNode } from 'react';
import { motion } from 'motion/react';

const spring = { type: 'spring' as const, stiffness: 400, damping: 17 };

/**
 * A card with a cursor-tracking radial glow effect.
 * Uses CSS custom properties for the glow position -- zero React re-renders.
 */
export function GlowCard({ children, className = '' }: { children: ReactNode; className?: string }) {
  const ref = useRef<HTMLDivElement>(null);

  const handleMouseMove = useCallback((e: React.MouseEvent<HTMLDivElement>) => {
    const el = ref.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    el.style.setProperty('--glow-x', `${e.clientX - rect.left}px`);
    el.style.setProperty('--glow-y', `${e.clientY - rect.top}px`);
  }, []);

  return (
    <motion.div
      ref={ref}
      className={`card-glow glass glass-hover transition-colors duration-300 cursor-pointer ${className}`}
      onMouseMove={handleMouseMove}
      whileHover={{ y: -4 }}
      whileTap={{ scale: 0.99 }}
      transition={spring}
    >
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-white/10 to-transparent" />
      {children}
    </motion.div>
  );
}
