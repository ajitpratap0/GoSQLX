'use client';
import { motion } from 'framer-motion';
import { ReactNode } from 'react';

export function GlassCard({ children, className = '', hover = true }: { children: ReactNode; className?: string; hover?: boolean }) {
  return (
    <motion.div
      className={`glass ${hover ? 'glass-hover transition-all duration-300' : ''} relative overflow-hidden ${className}`}
      whileHover={hover ? { scale: 1.02 } : undefined}
    >
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-white/10 to-transparent" />
      {children}
    </motion.div>
  );
}
