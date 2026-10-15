'use client';

import { LazyMotion, MotionConfig } from 'motion/react';

const loadFeatures = () => import('@/lib/motion-features').then((mod) => mod.default);

/**
 * Honours the OS reduced-motion setting for every motion component and
 * lazy-loads the animation feature bundle for the lightweight `m` components.
 */
export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <MotionConfig reducedMotion="user">
      <LazyMotion features={loadFeatures}>{children}</LazyMotion>
    </MotionConfig>
  );
}
