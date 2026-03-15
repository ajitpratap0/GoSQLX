'use client';

import { FadeIn } from '@/components/ui/FadeIn';
import { Button } from '@/components/ui/Button';

export default function NotFound() {
  return (
    <main className="min-h-screen flex items-center justify-center">
      <FadeIn className="text-center">
        <h1 className="text-4xl font-bold tracking-tight text-white">
          Page not found
        </h1>
        <p className="mt-4 text-lg text-zinc-400">
          The page you&apos;re looking for doesn&apos;t exist.
        </p>
        <div className="mt-8">
          <Button variant="primary" href="/">
            Back to Home
          </Button>
        </div>
      </FadeIn>
    </main>
  );
}
