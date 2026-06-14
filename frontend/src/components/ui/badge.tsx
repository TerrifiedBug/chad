import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@/lib/utils"

// VF "v2 console" Badge: 11px mono, 3px radius, status-color variants backed by
// the -bg (12%-opacity) fills. Every existing variant name is preserved
// (default/secondary/destructive/outline + success/warning/info and the
// *-subtle set) so app-wide usage + tests keep working.
const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-[3px] border px-1.5 py-0.5 font-mono text-[11px] font-medium leading-none transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
  {
    variants: {
      variant: {
        default:
          "border-transparent bg-primary text-primary-foreground hover:bg-primary/80",
        secondary:
          "border-transparent bg-secondary text-secondary-foreground hover:bg-secondary/80",
        destructive:
          "border-transparent bg-destructive text-destructive-foreground hover:bg-destructive/80",
        outline: "text-foreground border-line",
        // Semantic status variants — solid (status accent on -bg fill).
        success:
          "border-status-healthy/30 bg-status-healthy-bg text-status-healthy-foreground",
        warning:
          "border-status-degraded/30 bg-status-degraded-bg text-status-degraded-foreground",
        info:
          "border-status-info/30 bg-status-info-bg text-status-info-foreground",
        // Subtle semantic variants — same console fill grammar.
        "success-subtle":
          "border-status-healthy/20 bg-status-healthy-bg text-status-healthy-foreground",
        "warning-subtle":
          "border-status-degraded/20 bg-status-degraded-bg text-status-degraded-foreground",
        "info-subtle":
          "border-status-info/20 bg-status-info-bg text-status-info-foreground",
        "destructive-subtle":
          "border-status-error/20 bg-status-error-bg text-status-error-foreground",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
)

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  )
}

export { Badge, badgeVariants }
