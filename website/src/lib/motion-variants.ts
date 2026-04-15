import type { Variants, Transition } from 'motion/react';

// -- Shared animation variants --

/** Fade in from below -- use for sections, cards, any scroll-triggered content */
export const fadeInUp: Variants = {
  hidden: { opacity: 0, y: 20 },
  visible: { opacity: 1, y: 0 },
};

/** Fade in from left */
export const slideInLeft: Variants = {
  hidden: { opacity: 0, x: -30 },
  visible: { opacity: 1, x: 0 },
};

/** Fade in from right */
export const slideInRight: Variants = {
  hidden: { opacity: 0, x: 30 },
  visible: { opacity: 1, x: 0 },
};

/** Simple opacity fade */
export const fadeIn: Variants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1 },
};

/** Stagger container -- wraps children that each use fadeInUp/slideIn etc. */
export const staggerContainer: Variants = {
  hidden: {},
  visible: {
    transition: {
      staggerChildren: 0.06,
      delayChildren: 0.1,
    },
  },
};

/** Faster stagger for dense grids (8+ items) */
export const staggerContainerFast: Variants = {
  hidden: {},
  visible: {
    transition: {
      staggerChildren: 0.04,
      delayChildren: 0.05,
    },
  },
};

// -- Shared transitions --

export const defaultTransition: Transition = {
  duration: 0.4,
  ease: [0.25, 0.1, 0.25, 1],
};

export const springTransition: Transition = {
  type: 'spring',
  stiffness: 400,
  damping: 17,
};

// -- Shared gesture props (spread onto motion components) --

export const hoverLift = {
  whileHover: { y: -4 },
  transition: defaultTransition,
};

export const hoverScale = {
  whileHover: { scale: 1.02 },
  whileTap: { scale: 0.98 },
  transition: springTransition,
};

export const tapShrink = {
  whileTap: { scale: 0.97 },
  transition: springTransition,
};
