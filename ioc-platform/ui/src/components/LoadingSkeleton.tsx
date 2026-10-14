export function SkeletonCard() {
  return (
    <div className="bg-bg-card border border-border rounded-lg p-4 animate-pulse space-y-3" aria-busy="true" role="status" aria-label="Loading content">
      <div className="h-4 bg-bg-elevated rounded w-1/3" />
      <div className="h-3 bg-bg-elevated rounded w-2/3" />
      <div className="h-3 bg-bg-elevated rounded w-1/2" />
    </div>
  );
}

export function SkeletonHeader() {
  return (
    <div className="bg-bg-card border border-border rounded-lg p-5 animate-pulse flex items-center gap-5" aria-busy="true" role="status" aria-label="Loading header">
      <div className="w-20 h-20 bg-bg-elevated rounded-full" />
      <div className="space-y-2 flex-1">
        <div className="h-4 bg-bg-elevated rounded w-1/4" />
        <div className="h-6 bg-bg-elevated rounded w-1/2" />
        <div className="h-3 bg-bg-elevated rounded w-1/3" />
      </div>
    </div>
  );
}

export function SkeletonSourceGrid() {
  return (
    <div className="grid grid-cols-2 md:grid-cols-3 gap-3 items-start" aria-busy="true" role="status" aria-label="Loading sources">
      {Array.from({ length: 6 }).map((_, i) => (
        <SkeletonCard key={i} />
      ))}
    </div>
  );
}
