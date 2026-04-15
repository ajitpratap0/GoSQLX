'use client';

import { useRef } from 'react';
import { motion, useScroll, useTransform, useReducedMotion } from 'motion/react';
import { GlassCard } from '@/components/ui/GlassCard';
import { GradientText } from '@/components/ui/GradientText';
import { VersionBadge } from '@/components/ui/VersionBadge';
import { Button } from '@/components/ui/Button';
import { GitHubStarButton } from '@/components/home/GitHubStarButton';
import { MiniPlayground } from '@/components/home/MiniPlayground';

export function Hero() {
  const sectionRef = useRef<HTMLElement>(null);
  const shouldReduce = useReducedMotion();

  const { scrollYProgress } = useScroll({
    target: sectionRef,
    offset: ['start start', 'end start'],
  });

  // Parallax: orbs drift up slower than scroll
  const orbY1 = useTransform(scrollYProgress, [0, 1], ['0%', '-15%']);
  const orbY2 = useTransform(scrollYProgress, [0, 1], ['0%', '-25%']);
  const gridOpacity = useTransform(scrollYProgress, [0, 0.5], [0.05, 0]);

  // Content fades/scales slightly on scroll
  const contentY = useTransform(scrollYProgress, [0, 1], ['0%', '10%']);
  const contentOpacity = useTransform(scrollYProgress, [0, 0.6], [1, 0]);

  return (
    <section ref={sectionRef} className="relative min-h-screen flex items-center justify-center overflow-hidden">
      {/* Background gradient mesh -- floating orbs with parallax */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden" aria-hidden="true">
        {/* Top-right indigo glow -- floats */}
        <motion.div
          className={`absolute top-[-20%] right-[-10%] w-[60%] h-[60%] ${shouldReduce ? '' : 'animate-float-slow'}`}
          style={{
            background: 'radial-gradient(circle, rgba(99,102,241,0.15) 0%, transparent 60%)',
            filter: 'blur(80px)',
            y: shouldReduce ? 0 : orbY1,
          }}
        />
        {/* Bottom-left orange glow -- floats reverse */}
        <motion.div
          className={`absolute bottom-[-10%] left-[-10%] w-[50%] h-[50%] ${shouldReduce ? '' : 'animate-float-slow-reverse'}`}
          style={{
            background: 'radial-gradient(circle, rgba(249,115,22,0.08) 0%, transparent 60%)',
            filter: 'blur(60px)',
            y: shouldReduce ? 0 : orbY2,
          }}
        />
        {/* Subtle purple accent orb */}
        <motion.div
          className={`absolute top-[30%] left-[20%] w-[30%] h-[30%] ${shouldReduce ? '' : 'animate-float-slow'}`}
          style={{
            background: 'radial-gradient(circle, rgba(167,139,250,0.06) 0%, transparent 60%)',
            filter: 'blur(60px)',
            y: shouldReduce ? 0 : orbY2,
            animationDelay: '5s',
          }}
        />
        {/* Dot grid overlay -- drifts */}
        <motion.div
          className={`absolute inset-0 ${shouldReduce ? '' : 'animate-drift'}`}
          style={{
            backgroundImage: 'radial-gradient(rgba(255,255,255,0.5) 1px, transparent 1px)',
            backgroundSize: '24px 24px',
            opacity: shouldReduce ? 0.05 : gridOpacity,
          }}
        />
      </div>

      {/* Content -- parallax + fade on scroll */}
      <motion.div
        className="relative z-10 max-w-5xl mx-auto px-6 py-24 text-center"
        style={{
          y: shouldReduce ? 0 : contentY,
          opacity: shouldReduce ? 1 : contentOpacity,
        }}
      >
        {/* Version badge */}
        <motion.div
          className="mb-6"
          initial={{ opacity: 0, y: 20, scale: 0.95 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          transition={{ duration: 0.5, delay: 0.1 }}
        >
          <VersionBadge version="v1.14.0 - Multi-Dialect SQL Parser" />
        </motion.div>

        {/* Headline with shimmer */}
        <motion.h1
          className="text-3xl sm:text-5xl md:text-6xl lg:text-7xl font-bold mb-6 break-words hyphens-auto w-full max-w-full px-4 sm:px-0"
          style={{ letterSpacing: '-0.03em' }}
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.2, ease: [0.25, 0.1, 0.25, 1] }}
        >
          <GradientText shimmer>Parse SQL at the speed of Go</GradientText>
        </motion.h1>

        {/* Subtitle */}
        <motion.p
          className="text-lg md:text-xl max-w-2xl mx-auto mb-10 text-zinc-300"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.35 }}
        >
          Production-ready SQL parsing with zero-copy tokenization, object pooling, and multi-dialect support
        </motion.p>

        {/* Buttons */}
        <motion.div
          className="flex flex-wrap items-center justify-center gap-3 mb-14"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.45 }}
        >
          <Button variant="primary" href="/docs/getting-started">
            Get Started
          </Button>
          <Button variant="ghost" href="/playground">
            Try Playground
          </Button>
          <GitHubStarButton />
        </motion.div>

        {/* Live mini playground */}
        <motion.div
          initial={{ opacity: 0, y: 40, scale: 0.97 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          transition={{ duration: 0.7, delay: 0.55, ease: [0.25, 0.1, 0.25, 1] }}
        >
          <GlassCard hover={false} className="p-0 overflow-hidden shadow-2xl shadow-indigo-500/5">
            <MiniPlayground />
          </GlassCard>
        </motion.div>

      </motion.div>
    </section>
  );
}
