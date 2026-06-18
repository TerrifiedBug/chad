import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, FileBarChart, Play } from 'lucide-react'
import { reportSchedulesApi, statsApi, type ReportPreview } from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import { PageHeader } from '@/components/PageHeader'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { RelativeTime } from '@/components/RelativeTime'

const REPORT_TYPES = [
  { value: 'coverage', label: 'ATT&CK coverage' },
  { value: 'detection_kpis', label: 'Detection KPIs' },
  { value: 'rule_health', label: 'Rule health' },
  { value: 'compliance', label: 'Compliance' },
]
const FRAMEWORKS = [
  { value: 'pci_dss', label: 'PCI-DSS' },
  { value: 'soc2', label: 'SOC 2' },
  { value: 'iso_27001', label: 'ISO 27001' },
  { value: 'dora', label: 'DORA' },
]
const CADENCES = ['daily', 'weekly', 'monthly']

export default function Reports() {
  const { showToast } = useToast()
  const queryClient = useQueryClient()
  const [createOpen, setCreateOpen] = useState(false)
  const [name, setName] = useState('')
  const [reportType, setReportType] = useState('coverage')
  const [cadence, setCadence] = useState('weekly')
  const [framework, setFramework] = useState('pci_dss')
  const [deliveryTarget, setDeliveryTarget] = useState('')
  const [preview, setPreview] = useState<ReportPreview | null>(null)

  const { data: schedules = [] } = useQuery({ queryKey: ['report-schedules'], queryFn: () => reportSchedulesApi.list() })
  const { data: precision } = useQuery({
    queryKey: ['rule-precision'],
    queryFn: () => statsApi.getRulePrecision(30),
  })
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['report-schedules'] })
  const onErr = (err: unknown) => showToast(err instanceof Error ? err.message : 'Action failed', 'error')

  const create = useMutation({
    mutationFn: () => reportSchedulesApi.create({
      name: name.trim(), report_type: reportType, cadence,
      framework: reportType === 'compliance' ? framework : null,
      delivery_type: 'webhook', delivery_target: deliveryTarget || null,
    }),
    onSuccess: () => { invalidate(); setCreateOpen(false); setName(''); setDeliveryTarget(''); showToast('Report scheduled', 'success') },
    onError: onErr,
  })
  const remove = useMutation({
    mutationFn: (id: string) => reportSchedulesApi.remove(id),
    onSuccess: () => { invalidate(); showToast('Schedule deleted', 'success') }, onError: onErr,
  })
  const runNow = useMutation({
    mutationFn: (id: string) => reportSchedulesApi.run(id),
    onSuccess: (res) => { setPreview(res.report); showToast(res.delivered ? 'Delivered' : 'Built (no delivery target)', 'info') },
    onError: onErr,
  })
  const previewMut = useMutation({
    mutationFn: () => reportSchedulesApi.preview(reportType, reportType === 'compliance' ? framework : undefined),
    onSuccess: (res) => setPreview(res), onError: onErr,
  })

  return (
    <div className="space-y-6">
      <PageHeader
        title="Reports"
        description="Scheduled detection-posture and compliance reports (PCI-DSS, SOC 2, ISO 27001, DORA)."
        actions={
          <Button onClick={() => setCreateOpen(true)} className="gap-1.5"><Plus className="h-4 w-4" /> New schedule</Button>
        }
      />

      <div className="rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead className="w-36">Type</TableHead>
              <TableHead className="w-24">Cadence</TableHead>
              <TableHead className="w-24">Status</TableHead>
              <TableHead className="w-36">Next run</TableHead>
              <TableHead className="w-28 text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {schedules.length === 0 && (
              <TableRow><TableCell colSpan={6} className="py-8 text-center text-muted-foreground">
                <FileBarChart className="mx-auto mb-2 h-6 w-6 opacity-50" />No scheduled reports.
              </TableCell></TableRow>
            )}
            {schedules.map((s) => (
              <TableRow key={s.id}>
                <TableCell className="font-medium">{s.name}{s.framework && <Badge variant="secondary" className="ml-2 text-[10px] uppercase">{s.framework}</Badge>}</TableCell>
                <TableCell>{REPORT_TYPES.find((t) => t.value === s.report_type)?.label ?? s.report_type}</TableCell>
                <TableCell className="capitalize">{s.cadence}</TableCell>
                <TableCell><Badge variant={s.enabled ? 'secondary' : 'outline'}>{s.enabled ? 'Active' : 'Off'}</Badge></TableCell>
                <TableCell className="text-sm text-muted-foreground">{s.next_run_at ? <RelativeTime date={s.next_run_at} /> : '—'}</TableCell>
                <TableCell className="text-right">
                  <div className="flex items-center justify-end gap-1">
                    <Button variant="ghost" size="icon" aria-label="Run now" onClick={() => runNow.mutate(s.id)}><Play className="h-4 w-4" /></Button>
                    <Button variant="ghost" size="icon" aria-label="Delete" onClick={() => remove.mutate(s.id)}><Trash2 className="h-4 w-4 text-muted-foreground hover:text-destructive" /></Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">
            Rule precision leaderboard
            <span className="ml-2 text-xs font-normal text-muted-foreground">
              last {precision?.window_days ?? 30} days · noisiest first
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Rule</TableHead>
                <TableHead className="w-28 text-right">Precision</TableHead>
                <TableHead className="w-28 text-right">FP rate</TableHead>
                <TableHead className="w-28 text-right">Alerts/day</TableHead>
                <TableHead className="w-24 text-right">Total</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(precision?.rules ?? []).length === 0 && (
                <TableRow><TableCell colSpan={5} className="py-8 text-center text-muted-foreground">
                  No alert data in the selected window.
                </TableCell></TableRow>
              )}
              {(precision?.rules ?? []).map((r) => (
                <TableRow key={r.rule_id}>
                  <TableCell className="font-medium">{r.rule_title}</TableCell>
                  <TableCell className="text-right">{Math.round(r.precision_pct)}%</TableCell>
                  <TableCell className="text-right">
                    <Badge variant={r.fp_rate_pct >= 50 ? 'destructive' : 'secondary'}>
                      {Math.round(r.fp_rate_pct)}%
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right">{r.alerts_per_day}</TableCell>
                  <TableCell className="text-right">{r.total}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {preview && (
        <Card>
          <CardHeader className="flex-row items-center justify-between">
            <CardTitle className="text-sm">Preview — {preview.framework_name || preview.type}</CardTitle>
            <Button variant="ghost" size="sm" onClick={() => setPreview(null)}>Close</Button>
          </CardHeader>
          <CardContent>
            <pre className="max-h-96 overflow-auto rounded bg-muted p-3 text-xs">{JSON.stringify(preview, null, 2)}</pre>
          </CardContent>
        </Card>
      )}

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New report schedule</DialogTitle>
            <DialogDescription>Recurring report delivered to a webhook collector.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <Label htmlFor="rep-name">Name</Label>
              <Input id="rep-name" autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="Weekly coverage" />
            </div>
            <div className="flex gap-3">
              <div className="flex-1 space-y-1.5">
                <Label>Type</Label>
                <Select value={reportType} onValueChange={setReportType}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>{REPORT_TYPES.map((t) => <SelectItem key={t.value} value={t.value}>{t.label}</SelectItem>)}</SelectContent>
                </Select>
              </div>
              <div className="w-32 space-y-1.5">
                <Label>Cadence</Label>
                <Select value={cadence} onValueChange={setCadence}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>{CADENCES.map((c) => <SelectItem key={c} value={c} className="capitalize">{c}</SelectItem>)}</SelectContent>
                </Select>
              </div>
            </div>
            {reportType === 'compliance' && (
              <div className="space-y-1.5">
                <Label>Framework</Label>
                <Select value={framework} onValueChange={setFramework}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>{FRAMEWORKS.map((f) => <SelectItem key={f.value} value={f.value}>{f.label}</SelectItem>)}</SelectContent>
                </Select>
              </div>
            )}
            <div className="space-y-1.5">
              <Label htmlFor="rep-target">Delivery webhook URL</Label>
              <Input id="rep-target" value={deliveryTarget} onChange={(e) => setDeliveryTarget(e.target.value)} placeholder="https://siem.example.com/reports" />
            </div>
          </div>
          <DialogFooter className="sm:justify-between">
            <Button variant="ghost" onClick={() => previewMut.mutate()} disabled={previewMut.isPending}>Preview</Button>
            <div className="flex gap-2">
              <Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button>
              <Button onClick={() => create.mutate()} disabled={!name.trim() || create.isPending}>{create.isPending ? 'Saving…' : 'Create'}</Button>
            </div>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
