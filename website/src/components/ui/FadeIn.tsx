'use client';
import { motion, useReducedMotion } from 'framer-motion';
import { ReactNode, useState, useEffect, memo } from 'react';

export const FadeIn = memo(function FadeIn({ children, delay = 0, className = '' }: { children: ReactNode; delay?: number; className?: string }) {
  const shouldReduce = useReducedMotion();
  const [isMounted, setIsMounted] = useState(false);

  // Defer Framer Motion's initial state until after hydration. Without this,
  // Framer Motion applies initial={{ opacity: 0 }} before React hydrates, causing
  // the server-rendered HTML (opacity:1) to mismatch the client DOM (opacity:0).
  useEffect(() => {
    setIsMounted(true);
  }, []);

  if (!isMounted) {
    // Server + hydration pass: render without Framer Motion so the DOM matches
    // the server HTML exactly. No opacity/transform styles applied.
    return <div className={className}>{children}</div>;
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: shouldReduce ? 0 : 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: shouldReduce ? 0 : 0.5, delay: shouldReduce ? 0 : delay, ease: 'easeOut' }}
      className={className}
    >
      {children}
    </motion.div>
  );
});
