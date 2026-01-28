import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'

interface VersionData {
  name: string
  rule_a_id: string
  rule_b_id: string
  entity_field: string
  time_window_minutes: number
  severity: string
}

interface CorrelationRestoreDiffModalProps {
  isOpen: boolean
  onClose: () => void
  onConfirm: (reason: string) => void
  currentData: VersionData
  targetData: VersionData
  targetVersion: number
  currentVersion: number
  isRestoring: boolean
  targetChangeReason?: string
}

export function CorrelationRestoreDiffModal({
  isOpen,
  onClose,
  onConfirm,
  currentData,
  targetData,
  targetVersion,
  currentVersion,
  isRestoring,
  targetChangeReason,
}: CorrelationRestoreDiffModalProps) {
  const [reason, setReason] = useState('')

  const handleConfirm = () => {
    if (!reason.trim()) {
      return
    }
    onConfirm(reason)
    setReason('')
  }

  const handleClose = () => {
    setReason('')
    onClose()
  }

  const fields = [
    { label: 'Name', current: currentData.name, target: targetData.name },
    { label: 'Rule A', current: currentData.rule_a_id, target: targetData.rule_a_id },
    { label: 'Rule B', current: currentData.rule_b_id, target: targetData.rule_b_id },
    { label: 'Entity Field', current: currentData.entity_field, target: targetData.entity_field },
    { label: 'Time Window', current: `${currentData.time_window_minutes} min`, target: `${targetData.time_window_minutes} min` },
    { label: 'Severity', current: currentData.severity, target: targetData.severity },
  ]

  return (
    <Dialog open={isOpen} onOpenChange={(open) => !open && handleClose()}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Restore to Version {targetVersion}</DialogTitle>
          <DialogDescription>
            Review the changes that will be applied when restoring from v{currentVersion} to v{targetVersion}.
          </DialogDescription>
        </DialogHeader>

        <div className="my-4">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b">
                <th className="text-left py-2 font-medium">Field</th>
                <th className="text-left py-2 font-medium">Current (v{currentVersion})</th>
                <th className="text-left py-2 font-medium">Restoring to (v{targetVersion})</th>
              </tr>
            </thead>
            <tbody>
              {fields.map((field) => {
                const isChanged = field.current !== field.target
                return (
                  <tr key={field.label} className={isChanged ? 'bg-amber-50 dark:bg-amber-950/30' : ''}>
                    <td className="py-2 font-medium">{field.label}</td>
                    <td className={`py-2 ${isChanged ? 'text-red-600 dark:text-red-400 line-through' : ''}`}>
                      {field.current}
                    </td>
                    <td className={`py-2 ${isChanged ? 'text-green-600 dark:text-green-400 font-medium' : ''}`}>
                      {field.target}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>

        {targetChangeReason ? (
          <div className="text-sm text-muted-foreground italic border-l-2 border-primary pl-2 py-1">
            <span className="font-medium">Reason for v{targetVersion}:</span> "{targetChangeReason}"
          </div>
        ) : null}

        <div className="space-y-2 py-2">
          <Label htmlFor="restore-reason">Reason for Restore *</Label>
          <Textarea
            id="restore-reason"
            placeholder="Please explain why you are restoring to this version..."
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            rows={3}
            className="resize-none"
          />
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={handleClose} disabled={isRestoring}>
            Cancel
          </Button>
          <Button onClick={handleConfirm} disabled={!reason.trim() || isRestoring}>
            {isRestoring ? 'Restoring...' : `Restore to v${targetVersion}`}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
