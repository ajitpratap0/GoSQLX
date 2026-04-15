import { FadeIn } from '@/components/ui/FadeIn';
import { Button } from '@/components/ui/Button';

export function CtaBanner() {
  return (
    <section className="py-20 relative overflow-hidden">
      {/* Gradient mesh background -- breathing glow */}
      <div className="absolute inset-0 -z-10">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[400px] bg-accent-indigo/[0.07] rounded-full blur-[120px] animate-glow-pulse" />
        <div className="absolute top-1/3 left-1/4 w-[300px] h-[300px] bg-accent-purple/[0.05] rounded-full blur-[100px] animate-glow-pulse" style={{ animationDelay: '1.5s' }} />
        <div className="absolute bottom-1/3 right-1/4 w-[300px] h-[300px] bg-accent-orange/[0.04] rounded-full blur-[100px] animate-glow-pulse" style={{ animationDelay: '3s' }} />
      </div>

      <div className="max-w-6xl mx-auto px-4 text-center">
        <FadeIn viewport>
          <h2 className="text-3xl md:text-4xl font-bold text-white mb-6">
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
