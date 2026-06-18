import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { aiCopilotApi, type ExceptionSuggestion, type ExceptionOperator } from '@/lib/api'

const VALID_OPERATORS: ExceptionOperator[] = [
  'equals',
  'not_equals',
  'contains',
  'not_contains',
  'starts_with',
  'ends_with',
  'regex',
  'in_list',
]

function normalizeOperator(op: string): ExceptionOperator {
  return (VALID_OPERATORS as string[]).includes(op)
    ? (op as ExceptionOperator)
    : 'equals'
}

type ExceptionSuggestPanelProps = {
  ruleYaml: string
  falsePositiveExamples: Record<string, unknown>[]
  onUse: (s: { field: string; operator: ExceptionOperator; value: string }) => void
}

export function ExceptionSuggestPanel({
  ruleYaml,
  falsePositiveExamples,
  onUse,
}: ExceptionSuggestPanelProps) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [suggestions, setSuggestions] = useState<ExceptionSuggestion[]>([])

  const handleSuggest = async () => {
    setLoading(true)
    setError(null)
    try {
      const result = await aiCopilotApi.suggestExceptions({
        rule_yaml: ruleYaml,
        false_positive_examples: falsePositiveExamples,
      })
      setSuggestions(result.suggestions)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to get suggestions')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-3 rounded-md border border-border p-3">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium">AI exception suggestions</span>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={handleSuggest}
          disabled={loading}
        >
          {loading ? 'Suggesting...' : 'Suggest exceptions'}
        </Button>
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}

      {suggestions.length > 0 && (
        <ul className="space-y-2">
          {suggestions.map((s, idx) => (
            <li
              key={`${s.field}-${idx}`}
              className="flex items-start justify-between gap-3 rounded border border-border p-2"
            >
              <div className="min-w-0 space-y-1 text-sm">
                <div className="flex flex-wrap items-center gap-1">
                  <span className="font-mono">{s.field}</span>
                  <span className="text-muted-foreground">{s.operator}</span>
                  <span className="font-mono">{String(s.value)}</span>
                </div>
                {s.rationale && (
                  <p className="text-xs text-muted-foreground">{s.rationale}</p>
                )}
                {s.risk && (
                  <p className="text-xs text-amber-600 dark:text-amber-400">
                    Risk: {s.risk}
                  </p>
                )}
              </div>
              <Button
                type="button"
                variant="secondary"
                size="sm"
                onClick={() =>
                  onUse({
                    field: s.field,
                    operator: normalizeOperator(s.operator),
                    value: String(s.value),
                  })
                }
              >
                Use
              </Button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
