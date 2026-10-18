import type { Metadata } from 'next';
import { FadeIn } from '@/components/ui/FadeIn';
import { Button } from '@/components/ui/Button';

export const metadata: Metadata = {
  title: { absolute: 'Page not found | GoSQLX' },
  description: 'The page you are looking for does not exist. Return to the GoSQLX homepage.',
  robots: { index: false, follow: false },
};

export default function NotFound() {
  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="text-center">
        <FadeIn>
          <p className="text-sm font-semibold text-fg-muted uppercase tracking-wider mb-4">404</p>
        </FadeIn>
        <FadeIn delay={0.1}>
          <h1 className="text-4xl font-bold tracking-tight text-fg mb-4">
            Page not found
          </h1>
        </FadeIn>
        <FadeIn delay={0.2}>
          <p className="text-lg text-fg-muted mb-8">
            The page you&apos;re looking for doesn&apos;t exist.
          </p>
        </FadeIn>
        <FadeIn delay={0.3}>
          <Button variant="primary" href="/">Back to Home</Button>
        </FadeIn>
      </div>
    </div>
  );
}
