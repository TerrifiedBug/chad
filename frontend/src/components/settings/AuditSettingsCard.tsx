import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { auditSettingsApi, type AuditSettings } from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Switch } from '@/components/ui/switch'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Button } from '@/components/ui/button'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'

/**
 * Admin controls for audit hardening (I5): retention horizon, SIEM forwarding
 * (webhook, JSON/CEF, SSRF-validated), and PII redaction on export/forward.
 * The forward header value is write-only — never returned by the API.
 */
export function AuditSettingsCard() {
  const { showToast } = useToast()
  const queryClient = useQueryClient()
  const { data } = useQuery({ queryKey: ['audit-settings'], queryFn: () => auditSettingsApi.get() })

  const [s, setS] = useState<AuditSettings | null>(null)
  const [headerValue, setHeaderValue] = useState('')
  useEffect(() => {
    if (data) setS(data)
  }, [data])

  const save = useMutation({
    mutationFn: () =>
      auditSettingsApi.update({
        retention_days: s!.retention_days,
        forward: {
          enabled: s!.forward.enabled,
          format: s!.forward.format,
          url: s!.forward.url,
          header_name: s!.forward.header_name,
          header_value: headerValue || undefined,
        },
        redaction: s!.redaction,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['audit-settings'] })
      setHeaderValue('')
      showToast('Audit settings saved', 'success')
    },
    onError: (err) => showToast(err instanceof Error ? err.message : 'Failed to save', 'error'),
  })

  if (!s) return null

  return (
    <Card>
      <CardHeader>
        <CardTitle>Audit Hardening</CardTitle>
        <CardDescription>Retention, SIEM forwarding, and PII redaction for the audit trail.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="flex items-center justify-between gap-3">
          <div>
            <Label htmlFor="audit-retention">Retention (days)</Label>
            <p className="text-xs text-muted-foreground">0 = keep forever</p>
          </div>
          <Input
            id="audit-retention"
            type="number"
            min={0}
            className="w-28"
            value={s.retention_days}
            onChange={(e) => setS({ ...s, retention_days: Math.max(0, parseInt(e.target.value || '0', 10)) })}
          />
        </div>

        <div className="space-y-3 border-t pt-4">
          <div className="flex items-center justify-between">
            <div>
              <Label>SIEM forwarding</Label>
              <p className="text-xs text-muted-foreground">Ship audit events to an external collector.</p>
            </div>
            <Switch
              checked={s.forward.enabled}
              onCheckedChange={(enabled) => setS({ ...s, forward: { ...s.forward, enabled } })}
            />
          </div>
          {s.forward.enabled && (
            <div className="space-y-3">
              <div className="space-y-1.5">
                <Label htmlFor="audit-url">Collector URL</Label>
                <Input
                  id="audit-url"
                  placeholder="https://siem.example.com/ingest"
                  value={s.forward.url ?? ''}
                  onChange={(e) => setS({ ...s, forward: { ...s.forward, url: e.target.value } })}
                />
              </div>
              <div className="flex gap-3">
                <div className="space-y-1.5">
                  <Label>Format</Label>
                  <Select
                    value={s.forward.format}
                    onValueChange={(format) => setS({ ...s, forward: { ...s.forward, format } })}
                  >
                    <SelectTrigger className="w-32"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="json">JSON</SelectItem>
                      <SelectItem value="cef">CEF</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="flex-1 space-y-1.5">
                  <Label>Auth header name</Label>
                  <Input
                    placeholder="Authorization"
                    value={s.forward.header_name ?? ''}
                    onChange={(e) => setS({ ...s, forward: { ...s.forward, header_name: e.target.value } })}
                  />
                </div>
              </div>
              <div className="space-y-1.5">
                <Label>Auth header value {s.forward.has_header_value && <span className="text-xs text-muted-foreground">(set — leave blank to keep)</span>}</Label>
                <Input
                  type="password"
                  placeholder={s.forward.has_header_value ? '••••••••' : 'Bearer token'}
                  value={headerValue}
                  onChange={(e) => setHeaderValue(e.target.value)}
                />
              </div>
            </div>
          )}
        </div>

        <div className="space-y-2 border-t pt-4">
          <div className="flex items-center justify-between">
            <div>
              <Label>PII redaction on export</Label>
              <p className="text-xs text-muted-foreground">Redact these field names from exported/forwarded details.</p>
            </div>
            <Switch
              checked={s.redaction.enabled}
              onCheckedChange={(enabled) => setS({ ...s, redaction: { ...s.redaction, enabled } })}
            />
          </div>
          {s.redaction.enabled && (
            <Input
              value={s.redaction.fields.join(', ')}
              onChange={(e) => setS({ ...s, redaction: { ...s.redaction, fields: e.target.value.split(',').map((f) => f.trim()).filter(Boolean) } })}
              placeholder="email, user_email, ip_address"
            />
          )}
        </div>

        <div className="flex justify-end">
          <Button onClick={() => save.mutate()} disabled={save.isPending}>
            {save.isPending ? 'Saving…' : 'Save audit settings'}
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}
