'use client';
import dynamic from 'next/dynamic';

const Playground = dynamic(
  () => import('@/components/playground/Playground'),
  { ssr: false }
);

export default function PlaygroundLoader() {
  return <Playground />;
}
