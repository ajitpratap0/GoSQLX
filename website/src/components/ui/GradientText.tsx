export function GradientText({ children, className = '', shimmer = false }: { children: React.ReactNode; className?: string; shimmer?: boolean }) {
  const base = 'bg-gradient-to-r from-white via-zinc-200 to-zinc-400 bg-clip-text text-transparent';
  const shimmerCls = shimmer
    ? 'text-shimmer from-white via-indigo-200 to-zinc-400'
    : '';

  return (
    <span className={`${base} ${shimmerCls} ${className}`}>
      {children}
    </span>
  );
}
