import Link from 'next/link';

type ButtonProps = {
  variant?: 'primary' | 'ghost';
  href?: string;
  children: React.ReactNode;
  className?: string;
  external?: boolean;
  'aria-label'?: string;
};

export function Button({ variant = 'primary', href, children, className = '', external, 'aria-label': ariaLabel }: ButtonProps) {
  const base = variant === 'primary'
    ? 'bg-white text-zinc-950 hover:bg-zinc-200'
    : 'bg-white/[0.06] border border-white/[0.1] text-zinc-300 hover:bg-white/[0.1] hover:text-white';
  const cls = `inline-flex items-center gap-2 px-5 py-2.5 rounded-lg font-medium text-sm transition-all duration-200 ${base} ${className}`;

  if (href) {
    if (external) return <a href={href} target="_blank" rel="noopener noreferrer" className={cls} aria-label={ariaLabel}>{children}</a>;
    return <Link href={href} className={cls} aria-label={ariaLabel}>{children}</Link>;
  }
  return <button className={cls} aria-label={ariaLabel}>{children}</button>;
}
