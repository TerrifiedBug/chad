import * as React from "react"
import { cn } from "@/lib/utils"

/**
 * VF "v2 console" KPI strip: a border-divided horizontal strip of metric
 * tiles. Each tile shows a 28px mono accent value over a 10px uppercase mono
 * label, with an optional sublabel/delta. Use at the top of hub/list pages
 * (Dashboard, Approvals) as the dense console alternative to a StatCard grid.
 *
 * Tones map onto the semantic status palette so values read green/amber/red
 * without bespoke colours.
 */
type KpiTone = "default" | "accent" | "healthy" | "degraded" | "error" | "info"

const toneToValueClass: Record<KpiTone, string> = {
  default: "text-fg",
  accent: "text-accent-brand",
  healthy: "text-status-healthy",
  degraded: "text-status-degraded",
  error: "text-status-error",
  info: "text-status-info",
}

export interface KpiTileProps extends React.HTMLAttributes<HTMLDivElement> {
  label: string
  value: React.ReactNode
  sublabel?: React.ReactNode
  tone?: KpiTone
  icon?: React.ReactNode
}

const KpiTile = React.forwardRef<HTMLDivElement, KpiTileProps>(
  ({ label, value, sublabel, tone = "default", icon, className, onClick, ...props }, ref) => (
    <div
      ref={ref}
      onClick={onClick}
      className={cn(
        "flex flex-1 flex-col gap-1 px-5 py-4",
        onClick && "cursor-pointer transition-colors hover:bg-bg-3/40",
        className
      )}
      {...props}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="vf-thead text-fg-2">{label}</span>
        {icon && <span className="text-fg-3">{icon}</span>}
      </div>
      <span
        className={cn(
          "font-mono text-[28px] font-semibold leading-none tracking-tight tabular-nums",
          toneToValueClass[tone]
        )}
      >
        {value}
      </span>
      {sublabel && (
        <span className="vf-mono-xs text-fg-3">{sublabel}</span>
      )}
    </div>
  )
)
KpiTile.displayName = "KpiTile"

export type KpiStripProps = React.HTMLAttributes<HTMLDivElement>

const KpiStrip = React.forwardRef<HTMLDivElement, KpiStripProps>(
  ({ className, children, ...props }, ref) => (
    <div
      ref={ref}
      className={cn(
        // Border-divided flex strip: hairline frame + divider between tiles.
        "flex flex-col divide-y divide-line overflow-hidden rounded-[3px] border border-line bg-bg-2 sm:flex-row sm:divide-x sm:divide-y-0",
        className
      )}
      {...props}
    >
      {children}
    </div>
  )
)
KpiStrip.displayName = "KpiStrip"

export { KpiStrip, KpiTile }
