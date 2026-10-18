import { FadeIn } from '@/components/ui/FadeIn';
import { Button } from '@/components/ui/Button';

export function CtaBanner() {
  return (
    <section className="py-20 relative">
      {/* Glow: radial gradients that fade to transparent inside the section box.
          (Blurred blobs were clipped by the section, leaving hard rectangle edges.) */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 -z-10"
        style={{
          background: [
            'radial-gradient(ellipse 50% 50% at 50% 50%, color-mix(in srgb, var(--accent) 9%, transparent), transparent)',
            'radial-gradient(ellipse 25% 35% at 25% 40%, color-mix(in srgb, var(--accent) 6%, transparent), transparent)',
            'radial-gradient(ellipse 25% 35% at 75% 60%, color-mix(in srgb, var(--accent-warm) 5%, transparent), transparent)',
          ].join(', '),
        }}
      />

      <div className="max-w-6xl mx-auto px-4 text-center">
        <FadeIn viewport>
          <h2 className="text-3xl md:text-4xl font-bold text-fg mb-6">
            Ready to parse SQL at the speed of Go?
          </h2>
          <div className="flex flex-wrap items-center justify-center gap-4">
            <Button href="/docs/getting-started" variant="primary">
              Get Started
            </Button>
            <Button href="/playground" variant="ghost">
              Try Playground
            </Button>
          </div>
        </FadeIn>
      </div>
    </section>
  );
}
