import { useState, useEffect } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Alert, mispFeedbackApi, mispApi, MISPEventAttribute } from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Loader2, ExternalLink } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'

const THREAT_LEVELS = [
  { value: '1', label: 'High' },
  { value: '2', label: 'Medium' },
  { value: '3', label: 'Low' },
  { value: '4', label: 'Undefined' },
]

const DISTRIBUTIONS = [
  { value: '0', label: 'Your organization only' },
  { value: '1', label: 'This community only' },
  { value: '2', label: 'Connected communities' },
  { value: '3', label: 'All communities' },
]

const IOC_TYPES = [
  { value: 'ip-dst', label: 'Destination IP' },
  { value: 'ip-src', label: 'Source IP' },
  { value: 'domain', label: 'Domain' },
  { value: 'url', label: 'URL' },
  { value: 'md5', label: 'MD5' },
  { value: 'sha256', label: 'SHA256' },
  { value: 'filename', label: 'Filename' },
]

// Patterns to detect potential IOCs in log values
const IOC_PATTERNS: Record<string, RegExp> = {
  'ip-dst': /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
  'domain': /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/,
  'url': /^https?:\/\/.+/,
  'md5': /^[a-fA-F0-9]{32}$/,
  'sha256': /^[a-fA-F0-9]{64}$/,
}

interface ExtractedAttribute {
  field: string
  value: string
  type: string
  selected: boolean
}

interface CreateMISPEventDialogProps {
  alert: Alert
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function CreateMISPEventDialog({ alert, open, onOpenChange }: CreateMISPEventDialogProps) {
  const { showToast } = useToast()
  const [info, setInfo] = useState('')
  const [threatLevel, setThreatLevel] = useState('2')
  const [distribution, setDistribution] = useState('0')
  const [tags, setTags] = useState('source:chad')
  const [attributes, setAttributes] = useState<ExtractedAttribute[]>([])
  const [createdEventUrl, setCreatedEventUrl] = useState<string | null>(null)

  // Check MISP status
  const { data: mispStatus } = useQuery({
    queryKey: ['misp-status'],
    queryFn: () => mispApi.getStatus(),
  })

  // Extract potential IOCs from log document
  useEffect(() => {
    if (!open) return

    setInfo(`CHAD Alert: ${alert.rule_title}`)
    setCreatedEventUrl(null)

    const extracted: ExtractedAttribute[] = []
    const seen = new Set<string>()

    const extractFromObject = (obj: Record<string, unknown>, prefix = '') => {
      for (const [key, value] of Object.entries(obj)) {
        const fieldPath = prefix ? `${prefix}.${key}` : key

        if (typeof value === 'string' && value.length > 0 && value.length < 500) {
          // Check if value matches any IOC pattern
          for (const [type, pattern] of Object.entries(IOC_PATTERNS)) {
            if (pattern.test(value) && !seen.has(value)) {
              seen.add(value)
              extracted.push({
                field: fieldPath,
                value,
                type,
                selected: type === 'ip-dst' || type === 'domain' || type === 'md5' || type === 'sha256',
              })
              break
            }
          }
        } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
          extractFromObject(value as Record<string, unknown>, fieldPath)
        }
      }
    }

    extractFromObject(alert.log_document)
    setAttributes(extracted)
  }, [open, alert])

  const createMutation = useMutation({
    mutationFn: () => {
      const selectedAttrs: MISPEventAttribute[] = attributes
        .filter(a => a.selected)
        .map(a => ({
          type: a.type,
          value: a.value,
          to_ids: true,
        }))

      const tagList = tags.split(',').map(t => t.trim()).filter(Boolean)

      return mispFeedbackApi.createEvent({
        alert_id: alert.alert_id,
        info,
        threat_level: parseInt(threatLevel),
        distribution: parseInt(distribution),
        tags: tagList,
        attributes: selectedAttrs,
      })
    },
    onSuccess: (result) => {
      if (result.success && result.event_id) {
        showToast('MISP event created')
        if (mispStatus?.instance_url) {
          setCreatedEventUrl(`${mispStatus.instance_url}/events/view/${result.event_id}`)
        }
      } else {
        showToast(result.error || 'Failed to create event', 'error')
      }
    },
    onError: (err) => {
      showToast(err instanceof Error ? err.message : 'Failed to create event', 'error')
    },
  })

  const toggleAttribute = (index: number) => {
    setAttributes(prev => prev.map((a, i) =>
      i === index ? { ...a, selected: !a.selected } : a
    ))
  }

  const updateAttributeType = (index: number, type: string) => {
    setAttributes(prev => prev.map((a, i) =>
      i === index ? { ...a, type } : a
    ))
  }

  const selectedCount = attributes.filter(a => a.selected).length

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Create MISP Event</DialogTitle>
          <DialogDescription>
            Push this alert as a new threat intelligence event to MISP.
          </DialogDescription>
        </DialogHeader>

        {createdEventUrl ? (
          <div className="py-8 text-center space-y-4">
            <div className="text-lg font-medium text-green-600">Event Created Successfully</div>
            <a
              href={createdEventUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 text-primary hover:underline"
            >
              View in MISP
              <ExternalLink className="h-4 w-4" />
            </a>
          </div>
        ) : (
          <div className="space-y-4">
            <div>
              <Label>Event Info (title)</Label>
              <Input
                value={info}
                onChange={(e) => setInfo(e.target.value)}
                className="mt-1"
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label>Threat Level</Label>
                <Select value={threatLevel} onValueChange={setThreatLevel}>
                  <SelectTrigger className="mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {THREAT_LEVELS.map(({ value, label }) => (
                      <SelectItem key={value} value={value}>{label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label>Distribution</Label>
                <Select value={distribution} onValueChange={setDistribution}>
                  <SelectTrigger className="mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {DISTRIBUTIONS.map(({ value, label }) => (
                      <SelectItem key={value} value={value}>{label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div>
              <Label>Tags (comma-separated)</Label>
              <Input
                value={tags}
                onChange={(e) => setTags(e.target.value)}
                placeholder="source:chad, malware, apt"
                className="mt-1"
              />
            </div>

            <div>
              <Label>Attributes to Include ({selectedCount} selected)</Label>
              <div className="mt-2 border rounded-lg max-h-64 overflow-y-auto">
                {attributes.length === 0 ? (
                  <div className="p-4 text-center text-muted-foreground text-sm">
                    No potential IOCs detected in log document
                  </div>
                ) : (
                  <div className="divide-y">
                    {attributes.map((attr, idx) => (
                      <div key={idx} className="p-3 flex items-center gap-3">
                        <Checkbox
                          checked={attr.selected}
                          onCheckedChange={() => toggleAttribute(idx)}
                        />
                        <div className="flex-1 min-w-0">
                          <code className="text-sm font-mono break-all">{attr.value}</code>
                          <div className="text-xs text-muted-foreground">{attr.field}</div>
                        </div>
                        <Select
                          value={attr.type}
                          onValueChange={(type) => updateAttributeType(idx, type)}
                        >
                          <SelectTrigger className="w-36">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            {IOC_TYPES.map(({ value, label }) => (
                              <SelectItem key={value} value={value}>{label}</SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        <DialogFooter>
          {createdEventUrl ? (
            <Button onClick={() => onOpenChange(false)}>Close</Button>
          ) : (
            <>
              <Button variant="outline" onClick={() => onOpenChange(false)}>
                Cancel
              </Button>
              <Button
                onClick={() => createMutation.mutate()}
                disabled={createMutation.isPending || !info.trim()}
              >
                {createMutation.isPending && (
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                )}
                Create Event
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
