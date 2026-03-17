'use client';
import { useInView, useMotionValue, useSpring, useTransform } from 'framer-motion';
import { useRef, useEffect, useState } from 'react';

export function AnimatedCounter({ value, suffix = '', color = 'text-white' }: { value: number; suffix?: string; color?: string }) {
  const ref = useRef(null);
  const isInView = useInView(ref, { once: true });
  const motionValue = useMotionValue(0);
  const spring = useSpring(motionValue, { stiffness: 100, damping: 30 });
  const [display, setDisplay] = useState('0');

  useEffect(() => {
    if (isInView) motionValue.set(value);
  }, [isInView, value, motionValue]);

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
