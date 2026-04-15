'use client';
import { motion, useScroll, useReducedMotion } from 'motion/react';

export function ScrollProgressBar() {
  const { scrollYProgress } = useScroll();
  const shouldReduce = useReducedMotion();

  if (shouldReduce) return null;

  return (
    <motion.div
      style={{
        scaleX: scrollYProgress,
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        height: 3,
        zIndex: 9999,
        transformOrigin: '0%',
        background: 'linear-gradient(90deg, #6366f1, #8b5cf6, #a78bfa)',
      }}
    />
  );
}
