import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { useToast } from '@/components/ui/toast-provider'
import { Loader2, Sparkles } from 'lucide-react'
import { aiCopilotApi, type SummarizeAlertResponse } from '@/lib/api'
import { getErrorMessage } from '@/lib/errors'

interface AiAlertSummaryCardProps {
  /** The triggering log document to summarize. */
  logDocument: Record<string, unknown>
  /** Disable the trigger (e.g. when OpenSearch is offline or permission is missing). */
  disabled?: boolean
}

/**
 * Sidebar card that produces an analyst-friendly summary and recommended
 * actions for the current alert using the AI Detection Copilot. Self-contained:
 * it manages its own summarize mutation and renders the result inline.
 */
export function AiAlertSummaryCard({ logDocument, disabled = false }: AiAlertSummaryCardProps) {
  const { showToast } = useToast()
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const [result, setResult] = useState<SummarizeAlertResponse | null>(null)

  const summarize = useMutation({
    mutationFn: () => aiCopilotApi.summarizeAlert(logDocument),
    onSuccess: (data) => {
      setErrorMessage(null)
      setResult(data)
    },
    onError: (err) => {
      const message = getErrorMessage(err) || 'Failed to summarize alert'
      setErrorMessage(message)
      showToast(message, 'error')
    },
  })

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          <Sparkles className="h-4 w-4 text-primary" />
          AI Summary
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-xs text-muted-foreground">
          Generate an analyst summary and recommended actions for this alert
          using the configured AI Copilot.
        </p>

        <Button
          size="sm"
          className="w-full"
          onClick={() => summarize.mutate()}
          disabled={disabled || summarize.isPending}
        >
          {summarize.isPending ? (
            <>
              <Loader2 className="h-4 w-4 mr-1 animate-spin" />
              Summarizing…
            </>
          ) : (
            <>
              <Sparkles className="h-4 w-4 mr-1" />
              {result ? 'Regenerate with AI' : 'Summarize with AI'}
            </>
          )}
        </Button>

        {errorMessage && (
          <div className="bg-destructive/10 text-destructive text-xs p-2 rounded-md">
            {errorMessage}
          </div>
        )}

        {result && (
          <div className="space-y-3">
            {result.summary && (
              <p className="text-sm whitespace-pre-wrap">{result.summary}</p>
            )}
            {result.recommended_actions.length > 0 && (
              <div className="space-y-1.5">
                <div className="text-xs font-medium text-muted-foreground">
                  Recommended actions
                </div>
                <ul className="list-disc pl-5 space-y-1 text-sm">
                  {result.recommended_actions.map((action, i) => (
                    <li key={i}>{action}</li>
                  ))}
                </ul>
              </div>
            )}
            {!result.summary && result.recommended_actions.length === 0 && (
              <p className="text-xs text-muted-foreground">
                The model returned no summary. Try regenerating.
              </p>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
