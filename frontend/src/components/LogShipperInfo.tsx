import { useState } from 'react'
import { ChevronDown, ChevronUp, Copy, Check } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'

interface LogShipperInfoProps {
  percolatorIndex?: string
}

export function LogShipperInfo({ percolatorIndex }: LogShipperInfoProps) {
  const [isExpanded, setIsExpanded] = useState(false)
  const [copied, setCopied] = useState<string | null>(null)

  // Extract index suffix from percolator index (chad-percolator-{suffix} -> {suffix})
  const indexSuffix = percolatorIndex?.replace('chad-percolator-', '') || 'your-index-suffix'

  // Build the CHAD endpoint URL
  const chadEndpoint = `${window.location.origin}/api/logs/${indexSuffix}`

  const curlExample = `curl -X POST "${chadEndpoint}" \\
  -H "Content-Type: application/json" \\
  -d '[
    {"@timestamp":"2024-01-15T10:30:00Z","EventID":4625,"user":"admin"},
    {"@timestamp":"2024-01-15T10:31:00Z","EventID":4624,"user":"admin"}
  ]'`

  const fluentdExample = `<match logs.**>
  @type http
  endpoint ${chadEndpoint}
  open_timeout 2
  <format>
    @type json
  </format>
  <buffer>
    flush_interval 5s
  </buffer>
</match>`

  const copyToClipboard = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(id)
      setTimeout(() => setCopied(null), 2000)
    } catch (err) {
      console.error('Failed to copy:', err)
    }
  }

  return (
    <Card>
      <CardHeader
        className="cursor-pointer"
        onClick={() => setIsExpanded(!isExpanded)}
      >
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="text-base">Log Shipper Configuration</CardTitle>
            <CardDescription>
              How to send logs to CHAD for real-time rule matching
            </CardDescription>
          </div>
          <Button variant="ghost" size="icon">
            {isExpanded ? (
              <ChevronUp className="h-4 w-4" />
            ) : (
              <ChevronDown className="h-4 w-4" />
            )}
          </Button>
        </div>
      </CardHeader>

      {isExpanded && (
        <CardContent className="space-y-4">
          <div>
            <h4 className="font-medium mb-2">Overview</h4>
            <p className="text-sm text-muted-foreground">
              CHAD uses percolator queries to match incoming logs against deployed rules in real-time.
              Send your logs to CHAD's API endpoint, and CHAD will create alerts when rules match.
            </p>
          </div>

          <div>
            <h4 className="font-medium mb-2">Endpoint URL</h4>
            <div className="relative">
              <pre className="bg-muted p-3 rounded-md text-xs overflow-x-auto font-mono">
                POST {chadEndpoint}
              </pre>
              <Button
                variant="ghost"
                size="icon"
                className="absolute top-2 right-2 h-6 w-6"
                onClick={() => copyToClipboard(chadEndpoint, 'endpoint')}
              >
                {copied === 'endpoint' ? (
                  <Check className="h-3 w-3 text-green-500" />
                ) : (
                  <Copy className="h-3 w-3" />
                )}
              </Button>
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              Request body: JSON array of log documents
            </p>
          </div>

          <div>
            <h4 className="font-medium mb-2">Example: curl</h4>
            <div className="relative">
              <pre className="bg-muted p-3 rounded-md text-xs overflow-x-auto whitespace-pre-wrap">
                {curlExample}
              </pre>
              <Button
                variant="ghost"
                size="icon"
                className="absolute top-2 right-2 h-6 w-6"
                onClick={() => copyToClipboard(curlExample, 'curl')}
              >
                {copied === 'curl' ? (
                  <Check className="h-3 w-3 text-green-500" />
                ) : (
                  <Copy className="h-3 w-3" />
                )}
              </Button>
            </div>
          </div>

          <div>
            <h4 className="font-medium mb-2">Example: Fluentd Config</h4>
            <div className="relative">
              <pre className="bg-muted p-3 rounded-md text-xs overflow-x-auto whitespace-pre-wrap">
                {fluentdExample}
              </pre>
              <Button
                variant="ghost"
                size="icon"
                className="absolute top-2 right-2 h-6 w-6"
                onClick={() => copyToClipboard(fluentdExample, 'fluentd')}
              >
                {copied === 'fluentd' ? (
                  <Check className="h-3 w-3 text-green-500" />
                ) : (
                  <Copy className="h-3 w-3" />
                )}
              </Button>
            </div>
          </div>

          <div className="pt-2 border-t">
            <p className="text-xs text-muted-foreground">
              The endpoint does not require authentication - secure access at the network level.
              Each index pattern has its own endpoint based on the percolator index name.
            </p>
          </div>
        </CardContent>
      )}
    </Card>
  )
}
