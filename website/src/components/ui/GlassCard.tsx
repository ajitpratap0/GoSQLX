'use client';
import { motion } from 'framer-motion';
import { ReactNode } from 'react';

export function GlassCard({ children, className = '', hover = true }: { children: ReactNode; className?: string; hover?: boolean }) {
  return (
    <motion.div
      className={`glass ${hover ? 'glass-hover transition-all duration-300' : ''} ${className}`}
      whileHover={hover ? { scale: 1.02 } : undefined}
    >
      {children}
    </motion.div>
  );
}
