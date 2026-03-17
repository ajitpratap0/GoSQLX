import { Skeleton } from '@/components/ui/Skeleton';
export default function Loading() {
  return (
    <div className="max-w-4xl mx-auto px-6 py-20 space-y-6">
      <Skeleton className="h-10 w-64" />
      <Skeleton className="h-5 w-96" />
      <div className="space-y-4 pt-8">
        {[1,2,3,4,5].map(i => <Skeleton key={i} className="h-20 w-full" />)}
      </div>
    </div>
  );
}
