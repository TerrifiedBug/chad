import { useState, useEffect } from 'react'
import { IndexPattern, indexPatternsApi } from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import { Loader2, Save, X, Plus } from 'lucide-react'

interface SecurityTabProps {
  pattern: IndexPattern
  onPatternUpdated: (pattern: IndexPattern) => void
}

export function SecurityTab({ pattern, onPatternUpdated }: SecurityTabProps) {
  const { showToast } = useToast()
  const [allowedIps, setAllowedIps] = useState<string[]>(pattern.allowed_ips || [])
  const [newIpEntry, setNewIpEntry] = useState('')
  const [ipError, setIpError] = useState('')
  const [rateLimitEnabled, setRateLimitEnabled] = useState(pattern.rate_limit_enabled || false)
  const [rateLimitRequests, setRateLimitRequests] = useState<number | null>(
    pattern.rate_limit_requests_per_minute || 100
  )
  const [rateLimitEvents, setRateLimitEvents] = useState<number | null>(
    pattern.rate_limit_events_per_minute || 50000
  )
  const [isSaving, setIsSaving] = useState(false)

  // Reset form when pattern changes
  useEffect(() => {
    setAllowedIps(pattern.allowed_ips || [])
    setRateLimitEnabled(pattern.rate_limit_enabled || false)
    setRateLimitRequests(pattern.rate_limit_requests_per_minute || 100)
    setRateLimitEvents(pattern.rate_limit_events_per_minute || 50000)
  }, [pattern])

  const validateIp = (ip: string): boolean => {
    const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/
    const ipv6Pattern = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(\/\d{1,3})?$/
    return ipv4Pattern.test(ip) || ipv6Pattern.test(ip)
  }

  const handleAddIp = () => {
    const ip = newIpEntry.trim()
    if (!ip) return

    if (!validateIp(ip)) {
      setIpError('Invalid IP address or CIDR notation')
      return
    }

    if (allowedIps.includes(ip)) {
      setIpError('IP already in list')
      return
    }

    setAllowedIps([...allowedIps, ip])
    setNewIpEntry('')
    setIpError('')
  }

  const removeIp = (ip: string) => {
    setAllowedIps(allowedIps.filter(i => i !== ip))
  }

  const handleSave = async () => {
    setIsSaving(true)
    try {
      const updated = await indexPatternsApi.update(pattern.id, {
        allowed_ips: allowedIps.length > 0 ? allowedIps : null,
        rate_limit_enabled: rateLimitEnabled,
        rate_limit_requests_per_minute: rateLimitEnabled ? rateLimitRequests : null,
        rate_limit_events_per_minute: rateLimitEnabled ? rateLimitEvents : null,
      })
      onPatternUpdated(updated)
      showToast('Security settings saved')
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to save', 'error')
    } finally {
      setIsSaving(false)
    }
  }

  // This tab is only for push mode
  if (pattern.mode !== 'push') {
    return (
      <div className="text-center py-12 text-muted-foreground">
        <p>Security settings are only available for push mode index patterns.</p>
        <p className="text-sm">Pull mode patterns do not accept external log submissions.</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-medium">Security Settings</h3>
        <p className="text-sm text-muted-foreground">
          Configure IP restrictions and rate limiting for the log ingestion endpoint.
        </p>
      </div>

      {/* IP Allowlist */}
      <div className="space-y-4">
        <div>
          <Label className="text-base">IP Allowlist</Label>
          <p className="text-sm text-muted-foreground">
            Restrict log submissions to specific IP addresses or CIDR ranges.
            Leave empty to allow all IPs.
          </p>
        </div>

        <div className="flex gap-2">
          <Input
            value={newIpEntry}
            onChange={(e) => {
              setNewIpEntry(e.target.value)
              setIpError('')
            }}
            placeholder="192.168.1.0/24 or 10.0.0.1"
            className="font-mono"
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault()
                handleAddIp()
              }
            }}
          />
          <Button type="button" variant="secondary" onClick={handleAddIp}>
            <Plus className="h-4 w-4 mr-2" />
            Add
          </Button>
        </div>

        {ipError && <p className="text-sm text-destructive">{ipError}</p>}

        {allowedIps.length > 0 ? (
          <div className="flex flex-wrap gap-2">
            {allowedIps.map((ip) => (
              <Badge key={ip} variant="secondary" className="flex items-center gap-1 pr-1 font-mono">
                {ip}
                <button
                  type="button"
                  onClick={() => removeIp(ip)}
                  className="ml-1 hover:bg-muted rounded-full p-0.5"
                >
                  <X className="h-3 w-3" />
                </button>
              </Badge>
            ))}
          </div>
        ) : (
          <div className="text-sm text-muted-foreground py-4 text-center border border-dashed rounded-lg">
            No IP restrictions. All source IPs are allowed.
          </div>
        )}
      </div>

      {/* Rate Limiting */}
      <div className="space-y-4 pt-6 border-t">
        <div className="flex items-center justify-between">
          <div>
            <Label className="text-base">Rate Limiting</Label>
            <p className="text-sm text-muted-foreground">
              Limit the number of requests and events per minute from any single source.
            </p>
          </div>
          <Switch
            checked={rateLimitEnabled}
            onCheckedChange={setRateLimitEnabled}
          />
        </div>

        {rateLimitEnabled && (
          <div className="grid grid-cols-2 gap-4 pl-4 border-l-2">
            <div className="space-y-2">
              <Label htmlFor="rate-requests">Requests per minute</Label>
              <Input
                id="rate-requests"
                type="number"
                min="1"
                value={rateLimitRequests || ''}
                onChange={(e) => setRateLimitRequests(parseInt(e.target.value) || null)}
                placeholder="100"
              />
              <p className="text-xs text-muted-foreground">
                Maximum API requests per minute per source IP.
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="rate-events">Events per minute</Label>
              <Input
                id="rate-events"
                type="number"
                min="1"
                value={rateLimitEvents || ''}
                onChange={(e) => setRateLimitEvents(parseInt(e.target.value) || null)}
                placeholder="50000"
              />
              <p className="text-xs text-muted-foreground">
                Maximum log events per minute per source IP.
              </p>
            </div>
          </div>
        )}
      </div>

      <div className="flex justify-end pt-4 border-t">
        <Button onClick={handleSave} disabled={isSaving}>
          {isSaving ? (
            <>
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              Saving...
            </>
          ) : (
            <>
              <Save className="h-4 w-4 mr-2" />
              Save Changes
            </>
          )}
        </Button>
      </div>
    </div>
  )
}
