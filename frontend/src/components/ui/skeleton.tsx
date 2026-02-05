import { cn } from "@/lib/utils"

interface SkeletonProps extends React.HTMLAttributes<HTMLDivElement> {
  /** Animation variant */
  variant?: "pulse" | "shimmer"
}

function Skeleton({
  className,
  variant = "pulse",
  ...props
}: SkeletonProps) {
  return (
    <div
      className={cn(
        "rounded-md bg-muted",
        variant === "pulse" && "animate-pulse",
        variant === "shimmer" && "skeleton-shimmer",
        className
      )}
      {...props}
    />
  )
}

/** Skeleton for a single table row */
function SkeletonTableRow({ columns = 5 }: { columns?: number }) {
  return (
    <tr className="border-b">
      {Array.from({ length: columns }).map((_, i) => (
        <td key={i} className="p-4">
          <Skeleton className={cn(
            "h-4",
            i === 0 ? "w-24" : i === columns - 1 ? "w-16" : "w-32"
          )} />
        </td>
      ))}
    </tr>
  )
}

/** Skeleton for multiple table rows */
function SkeletonTable({ rows = 5, columns = 5 }: { rows?: number; columns?: number }) {
  return (
    <div className="w-full">
      <div className="border rounded-lg overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b bg-muted/50">
              {Array.from({ length: columns }).map((_, i) => (
                <th key={i} className="p-4 text-left">
                  <Skeleton className="h-4 w-20" />
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {Array.from({ length: rows }).map((_, i) => (
              <SkeletonTableRow key={i} columns={columns} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

/** Skeleton for a stat card */
function SkeletonStatCard() {
  return (
    <div className="rounded-lg border bg-card p-6 space-y-3">
      <div className="flex items-center justify-between">
        <Skeleton className="h-4 w-24" />
        <Skeleton className="h-8 w-8 rounded-md" />
      </div>
      <Skeleton className="h-8 w-16" />
      <Skeleton className="h-3 w-32" />
    </div>
  )
}

/** Skeleton for stat cards grid */
function SkeletonStatCards({ count = 4 }: { count?: number }) {
  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
      {Array.from({ length: count }).map((_, i) => (
        <SkeletonStatCard key={i} />
      ))}
    </div>
  )
}

/** Skeleton for a card with header and content */
function SkeletonCard() {
  return (
    <div className="rounded-lg border bg-card">
      <div className="p-6 space-y-2 border-b">
        <Skeleton className="h-5 w-32" />
        <Skeleton className="h-4 w-48" />
      </div>
      <div className="p-6 space-y-4">
        <Skeleton className="h-4 w-full" />
        <Skeleton className="h-4 w-3/4" />
        <Skeleton className="h-4 w-1/2" />
      </div>
    </div>
  )
}

/** Skeleton for settings category cards grid */
function SkeletonSettingsCards({ count = 6 }: { count?: number }) {
  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="rounded-lg border bg-card p-6 space-y-3">
          <div className="flex items-start justify-between">
            <Skeleton className="h-10 w-10 rounded-lg" />
            <Skeleton className="h-5 w-12 rounded-full" />
          </div>
          <Skeleton className="h-5 w-24 mt-3" />
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-20 mt-2" />
        </div>
      ))}
    </div>
  )
}

/** Skeleton for page header */
function SkeletonPageHeader() {
  return (
    <div className="space-y-2 mb-6">
      <Skeleton className="h-8 w-48" />
      <Skeleton className="h-4 w-72" />
    </div>
  )
}

/** Skeleton for a list item */
function SkeletonListItem() {
  return (
    <div className="flex items-center gap-4 p-4 border-b last:border-0">
      <Skeleton className="h-10 w-10 rounded-full" />
      <div className="flex-1 space-y-2">
        <Skeleton className="h-4 w-32" />
        <Skeleton className="h-3 w-48" />
      </div>
      <Skeleton className="h-8 w-20" />
    </div>
  )
}

/** Skeleton for a list */
function SkeletonList({ items = 5 }: { items?: number }) {
  return (
    <div className="rounded-lg border bg-card">
      {Array.from({ length: items }).map((_, i) => (
        <SkeletonListItem key={i} />
      ))}
    </div>
  )
}

export {
  Skeleton,
  SkeletonTableRow,
  SkeletonTable,
  SkeletonStatCard,
  SkeletonStatCards,
  SkeletonCard,
  SkeletonSettingsCards,
  SkeletonPageHeader,
  SkeletonListItem,
  SkeletonList,
}
