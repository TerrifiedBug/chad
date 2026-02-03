import { useState, useCallback } from 'react'
import { IndexPattern, indexPatternsApi } from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Check,
  Copy,
  Eye,
  EyeOff,
  RefreshCw,
  Database,
  Loader2,
  Clock,
} from 'lucide-react'

interface EndpointTabProps {
  pattern: IndexPattern
  onPatternUpdated?: (pattern: IndexPattern) => void
}

export function EndpointTab({ pattern, onPatternUpdated }: EndpointTabProps) {
  const { showToast } = useToast()
  const [visibleToken, setVisibleToken] = useState(false)
  const [copiedItem, setCopiedItem] = useState<string | null>(null)
  const [showRegenerateConfirm, setShowRegenerateConfirm] = useState(false)
  const [isRegenerating, setIsRegenerating] = useState(false)

  // Get index suffix from percolator index
  const getIndexSuffix = (percolatorIndex: string) => {
    return percolatorIndex.replace(/^chad-percolator-/, '')
  }

  // Copy to clipboard with feedback
  const copyToClipboard = useCallback(async (text: string, itemId: string) => {
    try {
      await navigator.clipboard.writeText(text)
      setCopiedItem(itemId)
      setTimeout(() => setCopiedItem(null), 2000)
    } catch {
      showToast('Failed to copy to clipboard', 'error')
    }
  }, [showToast])

  // Regenerate auth token
  const handleRegenerateToken = async () => {
    setIsRegenerating(true)
    try {
      const result = await indexPatternsApi.regenerateToken(pattern.id)
      showToast('Token regenerated successfully')
      setShowRegenerateConfirm(false)
      // Update parent with new token
      if (onPatternUpdated) {
        onPatternUpdated({ ...pattern, auth_token: result.auth_token })
      }
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to regenerate token', 'error')
    } finally {
      setIsRegenerating(false)
    }
  }

  // Pull Mode Content
  if (pattern.mode === 'pull') {
    return (
      <div className="space-y-6">
        <div className="p-4 bg-muted rounded-lg space-y-3">
          <div className="flex items-center gap-2">
            <Database className="h-5 w-5" />
            <span className="font-semibold">Pull Mode Active</span>
          </div>
          <p className="text-sm text-muted-foreground">
            CHAD automatically queries OpenSearch for logs matching the pattern
            <code className="mx-1 px-1 bg-background rounded text-xs">{pattern.pattern}</code>
            every <strong>{pattern.poll_interval_minutes} minutes</strong>.
          </p>
        </div>

        {/* Polling Configuration */}
        <div className="space-y-3">
          <Label className="text-sm font-medium">Polling Configuration</Label>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div className="p-3 border rounded-lg">
              <div className="flex items-center gap-2 text-muted-foreground mb-1">
                <Clock className="h-4 w-4" />
                <span>Poll Interval</span>
              </div>
              <span className="font-medium">{pattern.poll_interval_minutes} minutes</span>
            </div>
            <div className="p-3 border rounded-lg">
              <div className="flex items-center gap-2 text-muted-foreground mb-1">
                <Database className="h-4 w-4" />
                <span>Timestamp Field</span>
              </div>
              <code className="font-mono text-xs">{pattern.timestamp_field || '@timestamp'}</code>
            </div>
          </div>
        </div>

        <p className="text-xs text-muted-foreground">
          To switch to push mode for real-time detection, edit this pattern in the Settings tab.
        </p>
      </div>
    )
  }

  // Push Mode Content
  const indexSuffix = getIndexSuffix(pattern.percolator_index)

  return (
    <div className="space-y-6">
      {/* Endpoints */}
      <div className="space-y-3">
        <Label className="text-sm font-medium">Fluentd Endpoints</Label>

        {/* Standard (Synchronous) Endpoint */}
        <div className="space-y-1.5">
          <div className="text-xs text-muted-foreground font-medium">Standard (Synchronous)</div>
          <div className="flex gap-2">
            <code className="flex-1 text-xs bg-muted p-2 rounded font-mono break-all">
              POST {window.location.origin}/api/logs/{indexSuffix}
            </code>
            <Button
              variant="outline"
              size="icon"
              className="h-8 w-8"
              onClick={() => copyToClipboard(
                `${window.location.origin}/api/logs/${indexSuffix}`,
                'url-sync'
              )}
            >
              {copiedItem === 'url-sync' ? (
                <Check className="h-4 w-4 text-green-500" />
              ) : (
                <Copy className="h-4 w-4" />
              )}
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">
            Returns 200 OK after processing. Best for testing and lower volume.
          </p>
        </div>

        {/* Queue (Asynchronous) Endpoint */}
        <div className="space-y-1.5 p-3 border rounded-lg bg-muted/30">
          <div className="flex items-center gap-2">
            <span className="text-xs font-medium">Queue (Asynchronous)</span>
            <span className="text-xs text-green-600 dark:text-green-400 font-medium">Recommended</span>
          </div>
          <div className="flex gap-2">
            <code className="flex-1 text-xs bg-muted p-2 rounded font-mono break-all">
              POST {window.location.origin}/api/logs/{indexSuffix}/queue
            </code>
            <Button
              variant="outline"
              size="icon"
              className="h-8 w-8"
              onClick={() => copyToClipboard(
                `${window.location.origin}/api/logs/${indexSuffix}/queue`,
                'url-queue'
              )}
            >
              {copiedItem === 'url-queue' ? (
                <Check className="h-4 w-4 text-green-500" />
              ) : (
                <Copy className="h-4 w-4" />
              )}
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">
            Returns 202 immediately, processes in background. Best for production.
          </p>
        </div>
      </div>

      {/* Auth Token */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <Label className="text-sm font-medium">Auth Token</Label>
          <Button
            variant="ghost"
            size="sm"
            className="h-6 text-xs"
            onClick={() => setShowRegenerateConfirm(true)}
          >
            <RefreshCw className="h-3 w-3 mr-1" />
            Regenerate
          </Button>
        </div>
        <div className="flex gap-2">
          <code className="flex-1 text-xs bg-muted p-2 rounded font-mono break-all">
            {visibleToken
              ? pattern.auth_token
              : `${'*'.repeat(20)}...${pattern.auth_token.slice(-4)}`}
          </code>
          <Button
            variant="outline"
            size="icon"
            className="h-8 w-8"
            onClick={() => setVisibleToken(!visibleToken)}
          >
            {visibleToken ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
          </Button>
          <Button
            variant="outline"
            size="icon"
            className="h-8 w-8"
            onClick={() => copyToClipboard(pattern.auth_token, 'token')}
          >
            {copiedItem === 'token' ? (
              <Check className="h-4 w-4 text-green-500" />
            ) : (
              <Copy className="h-4 w-4" />
            )}
          </Button>
        </div>
      </div>

      {/* cURL Example */}
      <div className="space-y-2">
        <Label className="text-sm font-medium">Example Request</Label>
        <div className="relative">
          <pre className="text-xs bg-muted p-3 rounded font-mono overflow-x-auto whitespace-pre-wrap">
{`curl -X POST "${window.location.origin}/api/logs/${indexSuffix}" \\
  -H "Authorization: Bearer ${visibleToken ? pattern.auth_token : '<your-token>'}" \\
  -H "Content-Type: application/json" \\
  -d '[{"message": "test log", "timestamp": "${new Date().toISOString()}"}]'`}
          </pre>
          <Button
            variant="ghost"
            size="icon"
            className="absolute top-2 right-2 h-6 w-6"
            onClick={() => copyToClipboard(
              `curl -X POST "${window.location.origin}/api/logs/${indexSuffix}" \\\n  -H "Authorization: Bearer ${pattern.auth_token}" \\\n  -H "Content-Type: application/json" \\\n  -d '[{"message": "test log", "timestamp": "${new Date().toISOString()}"}]'`,
              'curl'
            )}
          >
            {copiedItem === 'curl' ? (
              <Check className="h-3 w-3 text-green-500" />
            ) : (
              <Copy className="h-3 w-3" />
            )}
          </Button>
        </div>
      </div>

      <p className="text-xs text-muted-foreground">
        Send a JSON array of log documents. Each log will be matched against deployed rules.
      </p>

      {/* Regenerate Token Confirmation */}
      <Dialog open={showRegenerateConfirm} onOpenChange={setShowRegenerateConfirm}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Regenerate Auth Token</DialogTitle>
            <DialogDescription>
              Are you sure you want to regenerate the auth token? This will immediately
              invalidate the existing token. Any log shippers using the old token will
              stop working until updated.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowRegenerateConfirm(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleRegenerateToken}
              disabled={isRegenerating}
            >
              {isRegenerating ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Regenerating...
                </>
              ) : (
                'Regenerate Token'
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
