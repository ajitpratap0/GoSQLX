export function GradientText({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return (
    <span className={`bg-gradient-to-r from-white via-zinc-200 to-zinc-400 bg-clip-text text-transparent ${className}`}>
      {children}
    </span>
  );
}
