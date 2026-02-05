import * as React from "react"
import { cn } from "@/lib/utils"

interface TableProps extends React.HTMLAttributes<HTMLTableElement> {
  /** Add ARIA role="grid" for keyboard navigable tables */
  navigable?: boolean
  /** Accessible label for the table */
  label?: string
}

const Table = React.forwardRef<HTMLTableElement, TableProps>(
  ({ className, navigable, label, ...props }, ref) => (
    <div className="relative w-full overflow-auto custom-scrollbar">
      <table
        ref={ref}
        role={navigable ? "grid" : undefined}
        aria-label={label}
        className={cn("w-full caption-bottom text-sm", className)}
        {...props}
      />
    </div>
  )
)
Table.displayName = "Table"

interface TableHeaderProps extends React.HTMLAttributes<HTMLTableSectionElement> {
  /** Make header sticky when scrolling */
  sticky?: boolean
}

const TableHeader = React.forwardRef<HTMLTableSectionElement, TableHeaderProps>(
  ({ className, sticky, ...props }, ref) => (
    <thead
      ref={ref}
      className={cn(
        "[&_tr]:border-b bg-muted/50",
        sticky && "sticky top-0 z-10 backdrop-blur-sm bg-background/95",
        className
      )}
      {...props}
    />
  )
)
TableHeader.displayName = "TableHeader"

interface TableBodyProps extends React.HTMLAttributes<HTMLTableSectionElement> {
  /** Enable zebra striping */
  striped?: boolean
}

const TableBody = React.forwardRef<HTMLTableSectionElement, TableBodyProps>(
  ({ className, striped, ...props }, ref) => (
    <tbody
      ref={ref}
      className={cn(
        "[&_tr:last-child]:border-0",
        striped && "table-striped",
        className
      )}
      {...props}
    />
  )
)
TableBody.displayName = "TableBody"

const TableFooter = React.forwardRef<
  HTMLTableSectionElement,
  React.HTMLAttributes<HTMLTableSectionElement>
>(({ className, ...props }, ref) => (
  <tfoot
    ref={ref}
    className={cn(
      "border-t bg-muted/50 font-medium [&>tr]:last:border-b-0",
      className
    )}
    {...props}
  />
))
TableFooter.displayName = "TableFooter"

interface TableRowProps extends React.HTMLAttributes<HTMLTableRowElement> {
  /** Whether to highlight this row as selected */
  selected?: boolean
  /** Whether this row is interactive/clickable */
  interactive?: boolean
  /** Enable keyboard navigation (adds tabIndex and focus styles) */
  focusable?: boolean
  /** Index for keyboard navigation */
  rowIndex?: number
}

const TableRow = React.forwardRef<HTMLTableRowElement, TableRowProps>(
  ({ className, selected, interactive, focusable, rowIndex, onKeyDown, ...props }, ref) => {
    const handleKeyDown = (e: React.KeyboardEvent<HTMLTableRowElement>) => {
      if (onKeyDown) {
        onKeyDown(e)
      }

      // Handle keyboard navigation
      if (focusable) {
        const row = e.currentTarget
        const tbody = row.parentElement

        if (e.key === 'ArrowDown') {
          e.preventDefault()
          const nextRow = row.nextElementSibling as HTMLTableRowElement | null
          nextRow?.focus()
        } else if (e.key === 'ArrowUp') {
          e.preventDefault()
          const prevRow = row.previousElementSibling as HTMLTableRowElement | null
          prevRow?.focus()
        } else if (e.key === 'Home' && tbody) {
          e.preventDefault()
          const firstRow = tbody.querySelector('tr[tabindex]') as HTMLTableRowElement | null
          firstRow?.focus()
        } else if (e.key === 'End' && tbody) {
          e.preventDefault()
          const rows = tbody.querySelectorAll('tr[tabindex]')
          const lastRow = rows[rows.length - 1] as HTMLTableRowElement | null
          lastRow?.focus()
        } else if (e.key === 'Enter' || e.key === ' ') {
          // Trigger click if row is interactive
          if (interactive && props.onClick) {
            e.preventDefault()
            row.click()
          }
        }
      }
    }

    return (
      <tr
        ref={ref}
        data-state={selected ? "selected" : undefined}
        tabIndex={focusable ? 0 : undefined}
        role={focusable ? "row" : undefined}
        aria-rowindex={rowIndex}
        onKeyDown={handleKeyDown}
        className={cn(
          "border-b transition-colors duration-150",
          "hover:bg-muted/50",
          "data-[state=selected]:bg-primary/5 data-[state=selected]:border-l-2 data-[state=selected]:border-l-primary",
          interactive && "cursor-pointer",
          focusable && "table-row-focusable",
          className
        )}
        {...props}
      />
    )
  }
)
TableRow.displayName = "TableRow"

const TableHead = React.forwardRef<
  HTMLTableCellElement,
  React.ThHTMLAttributes<HTMLTableCellElement>
>(({ className, ...props }, ref) => (
  <th
    ref={ref}
    className={cn(
      "h-12 px-4 text-left align-middle font-medium text-muted-foreground [&:has([role=checkbox])]:pr-0",
      className
    )}
    {...props}
  />
))
TableHead.displayName = "TableHead"

const TableCell = React.forwardRef<
  HTMLTableCellElement,
  React.TdHTMLAttributes<HTMLTableCellElement>
>(({ className, ...props }, ref) => (
  <td
    ref={ref}
    className={cn("p-4 align-middle [&:has([role=checkbox])]:pr-0", className)}
    {...props}
  />
))
TableCell.displayName = "TableCell"

const TableCaption = React.forwardRef<
  HTMLTableCaptionElement,
  React.HTMLAttributes<HTMLTableCaptionElement>
>(({ className, ...props }, ref) => (
  <caption
    ref={ref}
    className={cn("mt-4 text-sm text-muted-foreground", className)}
    {...props}
  />
))
TableCaption.displayName = "TableCaption"

export {
  Table,
  TableHeader,
  TableBody,
  TableFooter,
  TableHead,
  TableRow,
  TableCell,
  TableCaption,
}
