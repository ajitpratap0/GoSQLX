export function Skeleton({ className = '' }: { className?: string }) {
  return <div className={`animate-pulse bg-white/[0.06] rounded ${className}`} />;
}

export function DocsSkeleton() {
  return (
    <div className="space-y-4 p-8">
      <Skeleton className="h-8 w-3/4" />
      <Skeleton className="h-4 w-full" />
      <Skeleton className="h-4 w-5/6" />
      <Skeleton className="h-4 w-4/6" />
      <div className="pt-4 space-y-3">
        <Skeleton className="h-4 w-full" />
        <Skeleton className="h-4 w-full" />
        <Skeleton className="h-4 w-3/4" />
      </div>
    </div>
  );
}
