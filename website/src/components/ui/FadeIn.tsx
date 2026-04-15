'use client';
import { motion, useReducedMotion } from 'motion/react';
import { ReactNode, useState, useEffect, memo } from 'react';
import { fadeInUp, defaultTransition } from '@/lib/motion-variants';

interface FadeInProps {
  children: ReactNode;
  delay?: number;
  className?: string;
  /** Use whileInView (scroll-triggered) instead of animate-on-mount */
  viewport?: boolean;
}

export const FadeIn = memo(function FadeIn({ children, delay = 0, className = '', viewport = false }: FadeInProps) {
  const shouldReduce = useReducedMotion();
  const [isMounted, setIsMounted] = useState(false);

  useEffect(() => {
    setIsMounted(true);
  }, []);

  if (!isMounted) {
    return <div className={className}>{children}</div>;
  }

  const transition = {
    ...defaultTransition,
    duration: shouldReduce ? 0 : 0.5,
    delay: shouldReduce ? 0 : delay,
  };

  if (viewport) {
    return (
      <motion.div
        initial="hidden"
        whileInView="visible"
        viewport={{ once: true, amount: 0.1 }}
        variants={fadeInUp}
        transition={transition}
        className={className}
      >
        {children}
      </motion.div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: shouldReduce ? 0 : 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={transition}
      className={className}
    >
      {children}
    </motion.div>
  );
});
