import { useState } from 'react'
import { reportsApi } from '@/lib/api'
import { Button } from '@/components/ui/button'
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
import { Label } from '@/components/ui/label'
import { Download, FileSpreadsheet, FileText, Loader2 } from 'lucide-react'

interface RulesExportDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onError?: (message: string) => void
}

export function RulesExportDialog({ open, onOpenChange, onError }: RulesExportDialogProps) {
  const [exportFormat, setExportFormat] = useState<'csv' | 'pdf'>('pdf')
  const [isExporting, setIsExporting] = useState(false)

  const handleExport = async () => {
    setIsExporting(true)
    try {
      const blob = await reportsApi.generateRuleCoverage({
        format: exportFormat,
      })

      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      const dateStr = new Date().toISOString().slice(0, 10)
      a.download = `rule-coverage-${dateStr}.${exportFormat}`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      window.URL.revokeObjectURL(url)
      onOpenChange(false)
    } catch (err) {
      onError?.(err instanceof Error ? err.message : 'Export failed')
    } finally {
      setIsExporting(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Export Rules Report</DialogTitle>
          <DialogDescription>
            Generate a coverage report for all Sigma rules and correlation rules.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-4">
          <div className="space-y-2">
            <Label>Format</Label>
            <Select value={exportFormat} onValueChange={(v) => setExportFormat(v as 'csv' | 'pdf')}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="pdf">
                  <span className="flex items-center gap-2">
                    <FileText className="h-4 w-4" />
                    PDF
                  </span>
                </SelectItem>
                <SelectItem value="csv">
                  <span className="flex items-center gap-2">
                    <FileSpreadsheet className="h-4 w-4" />
                    CSV
                  </span>
                </SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={handleExport} disabled={isExporting}>
            {isExporting ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                Exporting...
              </>
            ) : (
              <>
                <Download className="h-4 w-4 mr-2" />
                Export
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
