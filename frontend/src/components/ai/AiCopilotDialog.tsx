import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { useToast } from '@/components/ui/toast-provider'
import { Loader2, Sparkles, Copy } from 'lucide-react'
import { aiCopilotApi, type GenerateRuleResponse } from '@/lib/api'
import { getErrorMessage } from '@/lib/errors'

interface AiCopilotDialogProps {
  /** Controlled open state. */
  open: boolean
  onOpenChange: (open: boolean) => void
  /**
   * Called when the user accepts a generated rule. The parent (e.g. the rule
   * editor) is responsible for inserting the YAML into its editor.
   */
  onApply: (yaml: string) => void
  /** Optional logsource hint to seed the request (e.g. "windows / process_creation"). */
  defaultLogsourceHint?: string
}

/**
 * Reusable dialog that drafts a Sigma rule from a natural-language prompt using
 * the AI Detection Copilot. Self-contained: it manages its own form state and
 * the generate mutation, and hands the resulting YAML back via `onApply`.
 */
export function AiCopilotDialog({
  open,
  onOpenChange,
  onApply,
  defaultLogsourceHint = '',
}: AiCopilotDialogProps) {
  const { showToast } = useToast()
  const [description, setDescription] = useState('')
  const [logsourceHint, setLogsourceHint] = useState(defaultLogsourceHint)
  const [result, setResult] = useState<GenerateRuleResponse | null>(null)

  const generate = useMutation({
    mutationFn: () =>
      aiCopilotApi.generateRule({
        description: description.trim(),
        logsource_hint: logsourceHint.trim() || null,
      }),
    onSuccess: (data) => {
      setResult(data)
    },
    onError: (err) => {
      showToast(getErrorMessage(err) || 'Failed to generate rule', 'error')
    },
  })

  const handleOpenChange = (next: boolean) => {
    if (!next) {
      // Reset transient state when the dialog closes so it reopens clean.
      setResult(null)
      generate.reset()
    }
    onOpenChange(next)
  }

  const handleApply = () => {
    if (result?.yaml) {
      onApply(result.yaml)
      showToast('Generated rule applied', 'success')
      handleOpenChange(false)
    }
  }

  const handleCopy = async () => {
    if (result?.yaml) {
      await navigator.clipboard.writeText(result.yaml)
      showToast('Copied to clipboard', 'success')
    }
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-primary" />
            Generate rule with AI
          </DialogTitle>
          <DialogDescription>
            Describe the behaviour you want to detect. The Copilot drafts a Sigma
            rule you can review and insert into the editor.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="ai-copilot-description">Detection description</Label>
            <Textarea
              id="ai-copilot-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="e.g. Detect PowerShell launching an encoded command from a parent Office process"
              rows={4}
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="ai-copilot-logsource">Logsource hint (optional)</Label>
            <Input
              id="ai-copilot-logsource"
              value={logsourceHint}
              onChange={(e) => setLogsourceHint(e.target.value)}
              placeholder="e.g. windows / process_creation"
            />
          </div>

          {result && (
            <div className="space-y-1.5">
              {result.explanation && (
                <p className="text-sm text-muted-foreground">{result.explanation}</p>
              )}
              <div className="flex items-center justify-between">
                <Label>Generated rule</Label>
                <Button variant="ghost" size="sm" onClick={handleCopy}>
                  <Copy className="h-3 w-3" />
                  Copy
                </Button>
              </div>
              <pre className="max-h-64 overflow-auto rounded-[3px] border border-line bg-bg-2 p-3 text-xs">
                <code>{result.yaml}</code>
              </pre>
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => handleOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={() => generate.mutate()}
            disabled={generate.isPending || !description.trim()}
          >
            {generate.isPending ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Generating…
              </>
            ) : (
              <>
                <Sparkles className="h-4 w-4" />
                {result ? 'Regenerate' : 'Generate'}
              </>
            )}
          </Button>
          {result?.yaml && (
            <Button onClick={handleApply}>Apply to editor</Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
