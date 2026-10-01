'use client'

/**
 * Shared loading placeholders.
 *
 * Most Vectra pages stream data through Firestore listeners that start with an
 * empty array. Without a "first snapshot has arrived" flag those pages render
 * their empty state ("No findings yet") before any data exists, which reads as
 * broken rather than loading. These placeholders mirror the real layouts so the
 * page keeps its shape while data is on the way.
 */

import { Skeleton } from '@/components/ui/skeleton'
import { Card, CardContent } from '@/components/ui/card'

/** Row of stat cards, matching the dashboard/overview tiles. */
export function StatCardsSkeleton({ count = 4 }: { count?: number }) {
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
      {Array.from({ length: count }).map((_, i) => (
        <Card key={i} className="bg-card border-foreground/10">
          <CardContent className="p-4 space-y-2.5">
            <Skeleton className="h-3 w-20" />
            <Skeleton className="h-7 w-14" />
            <Skeleton className="h-2.5 w-24" />
          </CardContent>
        </Card>
      ))}
    </div>
  )
}

/** Table body placeholder — keeps column rhythm so the header doesn't jump. */
export function TableSkeleton({ rows = 6, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div className="space-y-2" aria-hidden="true">
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="flex items-center gap-4 py-2.5 border-b border-foreground/5">
          {Array.from({ length: cols }).map((_, c) => (
            <Skeleton
              key={c}
              className="h-4"
              style={{ width: c === 0 ? '28%' : c === cols - 1 ? '12%' : `${Math.round(60 / (cols - 1))}%` }}
            />
          ))}
        </div>
      ))}
    </div>
  )
}

/** Stack of list/selection cards (scan lists, report targets). */
export function ListSkeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div className="space-y-2" aria-hidden="true">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="p-4 rounded-lg border border-foreground/10">
          <div className="flex items-start justify-between gap-3">
            <div className="flex-1 space-y-2">
              <Skeleton className="h-4 w-1/3" />
              <div className="flex gap-2">
                <Skeleton className="h-3 w-16" />
                <Skeleton className="h-3 w-24" />
              </div>
            </div>
            <div className="space-y-1.5 text-right">
              <Skeleton className="h-3 w-20 ml-auto" />
              <Skeleton className="h-3 w-14 ml-auto" />
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}

/** Card-shaped placeholder for a detail panel. */
export function CardSkeleton({ lines = 3 }: { lines?: number }) {
  return (
    <Card className="bg-card border-foreground/10">
      <CardContent className="p-4 space-y-3">
        <Skeleton className="h-4 w-40" />
        {Array.from({ length: lines }).map((_, i) => (
          <Skeleton key={i} className="h-3" style={{ width: `${90 - i * 12}%` }} />
        ))}
      </CardContent>
    </Card>
  )
}

/** Full page placeholder used while a route's primary data loads. */
export function PageSkeleton({
  stats = 4,
  rows = 6,
  cols = 5,
}: { stats?: number; rows?: number; cols?: number }) {
  return (
    <div className="space-y-6" aria-busy="true" aria-live="polite">
      <div className="space-y-2">
        <Skeleton className="h-6 w-48" />
        <Skeleton className="h-3 w-72" />
      </div>
      {stats > 0 && <StatCardsSkeleton count={stats} />}
      <Card className="bg-card border-foreground/10">
        <CardContent className="p-4">
          <TableSkeleton rows={rows} cols={cols} />
        </CardContent>
      </Card>
    </div>
  )
}
