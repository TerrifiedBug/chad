import { useMemo } from 'react'
import { diffLines, Change } from 'diff'
import { cn } from '@/lib/utils'

/**
 * Coerce a diff side to text. Strings pass through; objects (e.g. the deploy
 * preview's OpenSearch DSL ``query`` — typed as string but sent as an object)
 * render as pretty JSON instead of "[object Object]"; null/undefined → "".
 */
function toDiffText(value: unknown): string {
  if (value == null) return ''
  if (typeof value === 'string') return value
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return String(value)
  }
}

interface YamlDiffProps {
  /** The current/deployed content (the "before" side, rendered as removals). */
  current: string
  /** The proposed/target content (the "after" side, rendered as additions). */
  proposed: string
  className?: string
}

/**
 * Renders a line-by-line YAML diff between two strings. Added lines are shown
 * green with a `+` prefix, removed lines red with a `-` prefix, unchanged lines
 * neutral. Extracted from RestoreDiffModal so it can be reused by the deployment
 * approval detail panel (deployed_yaml = current, proposed_yaml = proposed).
 */
export function YamlDiff({ current, proposed, className }: YamlDiffProps) {
  // toDiffText guards the `diff` library (which calls `.split` internally and
  // throws on null/undefined) AND renders DSL objects as pretty JSON rather
  // than "[object Object]".
  const diff = useMemo(
    () => diffLines(toDiffText(current), toDiffText(proposed)),
    [current, proposed]
  )

  return (
    <div
      className={cn(
        'overflow-auto border rounded-md bg-muted/50 p-4 font-mono text-sm',
        className
      )}
    >
      {diff.map((part: Change, index: number) => {
        const lines = String(part.value ?? '').split('\n').filter((_: string, i: number, arr: string[]) =>
          i < arr.length - 1 || arr[i] !== ''
        )

        return lines.map((line: string, lineIndex: number) => {
          let lineClassName = ''
          let prefix = ' '

          if (part.added) {
            lineClassName = 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-200'
            prefix = '+'
          } else if (part.removed) {
            lineClassName = 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-200'
            prefix = '-'
          }

          return (
            <div key={`${index}-${lineIndex}`} className={lineClassName}>
              <span className="select-none text-muted-foreground mr-2">{prefix}</span>
              {line}
            </div>
          )
        })
      })}
    </div>
  )
}
