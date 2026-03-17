'use client';
import { useMotionValue, useSpring } from 'framer-motion';
import { useRef, useEffect, useState } from 'react';

export function AnimatedCounter({ value, suffix = '', color = 'text-white' }: { value: number; suffix?: string; color?: string }) {
  const ref = useRef(null);
  const motionValue = useMotionValue(0);
  const spring = useSpring(motionValue, { stiffness: 100, damping: 30 });
  const [display, setDisplay] = useState(() => value.toLocaleString());

  useEffect(() => {
    // Respect prefers-reduced-motion
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      setDisplay(value.toLocaleString());
      return;
    }
    // Start animation after a short delay to ensure mount has completed
    const timer = setTimeout(() => {
      motionValue.set(value);
    }, 200);
    return () => clearTimeout(timer);
  }, [value, motionValue]);

  useEffect(() => {
    const unsubscribe = spring.on('change', (v: number) => {
      setDisplay(Math.round(v).toLocaleString());
    });
    return unsubscribe;
  }, [spring]);

  return (
    <span ref={ref} className={`text-4xl font-bold tabular-nums ${color}`}>
      {display}{suffix}
    </span>
  );
}
