'use client';
import { motion } from 'motion/react';
import { ReactNode } from 'react';

const spring = { type: 'spring' as const, stiffness: 400, damping: 17 };

export function GlassCard({ children, className = '', hover = true }: { children: ReactNode; className?: string; hover?: boolean }) {
  return (
    <motion.div
      className={`glass ${hover ? 'glass-hover transition-colors duration-300' : ''} relative overflow-hidden ${className}`}
      whileHover={hover ? { scale: 1.02, y: -2 } : undefined}
      whileTap={hover ? { scale: 0.99 } : undefined}
      transition={spring}
    >
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-white/10 to-transparent" />
      {children}
    </motion.div>
  );
}
