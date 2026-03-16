'use client';
import dynamic from 'next/dynamic';
import { WasmErrorBoundary } from '@/components/playground/WasmErrorBoundary';

const Playground = dynamic(
  () => import('@/components/playground/Playground'),
  { ssr: false }
);

export default function PlaygroundLoader() {
  return (
    <WasmErrorBoundary>
      <Playground />
    </WasmErrorBoundary>
  );
}
