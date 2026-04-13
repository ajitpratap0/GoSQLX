import Image from 'next/image';
import { FadeInCSS } from '@/components/ui/FadeInCSS';

const badges = [
  {
    alt: 'GitHub Stars',
    src: 'https://img.shields.io/github/stars/ajitpratap0/GoSQLX?style=flat-square&color=6366f1&labelColor=18181b',
    width: 100,
    height: 20,
  },
  {
    alt: 'Tests',
    src: 'https://img.shields.io/badge/tests-passing-22c55e?style=flat-square&labelColor=18181b',
    width: 96,
    height: 20,
  },
  {
    alt: 'Go Report Card',
    src: 'https://img.shields.io/badge/Go_Report-A+-22c55e?style=flat-square&labelColor=18181b',
    width: 110,
    height: 20,
  },
  {
    alt: 'GoDoc',
    src: 'https://img.shields.io/badge/GoDoc-reference-6366f1?style=flat-square&labelColor=18181b',
    width: 120,
    height: 20,
  },
];

export function SocialProof() {
  return (
    <section className="py-8 border-t border-white/[0.06]">
      <div className="max-w-6xl mx-auto px-4">
        <FadeInCSS>
          <div className="flex flex-wrap items-center justify-center gap-4">
            {badges.map((badge) => (
              <Image
                key={badge.alt}
                src={badge.src}
                alt={badge.alt}
                width={badge.width}
                height={badge.height}
                className="h-5 w-auto"
                loading="lazy"
                unoptimized
              />
            ))}
          </div>
        </FadeInCSS>
      </div>
    </section>
  );
}
