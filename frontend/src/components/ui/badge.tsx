import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@/lib/utils"

const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
  {
    variants: {
      variant: {
        default:
          "border-transparent bg-primary text-primary-foreground shadow-sm hover:bg-primary/80",
        secondary:
          "border-transparent bg-secondary text-secondary-foreground hover:bg-secondary/80",
        destructive:
          "border-transparent bg-destructive text-destructive-foreground shadow-sm hover:bg-destructive/80",
        outline: "text-foreground border-border",
        // Semantic status variants - solid
        success:
          "border-transparent bg-green-500 text-white shadow-sm hover:bg-green-600",
        warning:
          "border-transparent bg-yellow-500 text-black shadow-sm hover:bg-yellow-600",
        info:
          "border-transparent bg-blue-500 text-white shadow-sm hover:bg-blue-600",
        // Subtle semantic variants (with border) - more refined
        "success-subtle":
          "border-green-500/20 bg-green-500/10 text-green-700 dark:text-green-400 dark:border-green-500/30",
        "warning-subtle":
          "border-yellow-500/20 bg-yellow-500/10 text-yellow-700 dark:text-yellow-400 dark:border-yellow-500/30",
        "info-subtle":
          "border-blue-500/20 bg-blue-500/10 text-blue-700 dark:text-blue-400 dark:border-blue-500/30",
        "destructive-subtle":
          "border-red-500/20 bg-red-500/10 text-red-700 dark:text-red-400 dark:border-red-500/30",
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
