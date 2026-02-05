import { useState, useEffect, useMemo } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Alert, mispFeedbackApi, mispApi, MISPEventAttribute } from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
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
import { SearchableFieldSelect } from '@/components/ui/searchable-field-select'
import { Loader2, ExternalLink, X, Plus } from 'lucide-react'
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
  { value: 'sha1', label: 'SHA1' },
  { value: 'filename', label: 'Filename' },
  { value: 'email-src', label: 'Email (source)' },
  { value: 'email-dst', label: 'Email (destination)' },
  { value: 'hostname', label: 'Hostname' },
]

interface SelectedAttribute {
  field: string
  value: string
  type: string
}

interface FieldInfo {
  path: string
  value: string
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
  const [attributes, setAttributes] = useState<SelectedAttribute[]>([])
  const [createdEventUrl, setCreatedEventUrl] = useState<string | null>(null)

  // Check MISP status
  const { data: mispStatus } = useQuery({
    queryKey: ['misp-status'],
    queryFn: () => mispApi.getStatus(),
  })

  // Extract all string fields from log document for selection
  const availableFields = useMemo(() => {
    const fields: FieldInfo[] = []

    const extractFromObject = (obj: Record<string, unknown>, prefix = '') => {
      for (const [key, value] of Object.entries(obj)) {
        const fieldPath = prefix ? `${prefix}.${key}` : key

        if (typeof value === 'string' && value.length > 0 && value.length < 500) {
          fields.push({ path: fieldPath, value })
        } else if (typeof value === 'number') {
          fields.push({ path: fieldPath, value: String(value) })
        } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
          extractFromObject(value as Record<string, unknown>, fieldPath)
        }
      }
    }

    extractFromObject(alert.log_document)
    return fields
  }, [alert.log_document])

  // Field paths for the searchable select
  const fieldPaths = useMemo(() =>
    availableFields.map(f => f.path).sort(),
    [availableFields]
  )

  // Already selected field paths
  const selectedPaths = useMemo(() =>
    attributes.map(a => a.field),
    [attributes]
  )

  // Reset state when dialog opens
  useEffect(() => {
    if (!open) return
    setInfo(`CHAD Alert: ${alert.rule_title}`)
    setCreatedEventUrl(null)
    setAttributes([])
  }, [open, alert])

  const addAttribute = (fieldPath: string) => {
    const fieldInfo = availableFields.find(f => f.path === fieldPath)
    if (!fieldInfo) return

    setAttributes(prev => [
      ...prev,
      {
        field: fieldPath,
        value: fieldInfo.value,
        type: 'ip-dst', // Default type
      },
    ])
  }

  const removeAttribute = (index: number) => {
    setAttributes(prev => prev.filter((_, i) => i !== index))
  }

  const updateAttributeType = (index: number, type: string) => {
    setAttributes(prev => prev.map((a, i) =>
      i === index ? { ...a, type } : a
    ))
  }

  const createMutation = useMutation({
    mutationFn: () => {
      const selectedAttrs: MISPEventAttribute[] = attributes.map(a => ({
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

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
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
          <div className="space-y-4 max-h-[60vh] overflow-y-auto pr-2">
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
              <Label className="flex items-center gap-2">
                <Plus className="h-4 w-4" />
                Add IOC Attributes
              </Label>
              <p className="text-xs text-muted-foreground mt-1 mb-2">
                Select fields from the alert log to include as IOC attributes.
              </p>
              <SearchableFieldSelect
                fields={fieldPaths}
                placeholder="Search for a field to add..."
                onSelect={addAttribute}
                clearOnSelect={true}
                excludeFields={selectedPaths}
                maxDropdownHeight="12rem"
              />
            </div>

            {attributes.length > 0 && (
              <div>
                <Label>Selected Attributes ({attributes.length})</Label>
                <div className="mt-2 border rounded-lg divide-y">
                  {attributes.map((attr, idx) => (
                    <div key={idx} className="p-3 flex items-start gap-3">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <Badge variant="outline" className="text-xs font-mono">
                            {attr.field}
                          </Badge>
                        </div>
                        <code className="text-sm font-mono break-all text-muted-foreground">
                          {attr.value}
                        </code>
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
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8 text-muted-foreground hover:text-destructive"
                        onClick={() => removeAttribute(idx)}
                      >
                        <X className="h-4 w-4" />
                      </Button>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {attributes.length === 0 && (
              <div className="text-sm text-muted-foreground py-4 text-center border border-dashed rounded-lg">
                No attributes added yet. Use the field selector above to add IOC values.
              </div>
            )}
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
