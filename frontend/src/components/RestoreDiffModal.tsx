import { useMemo, useState } from 'react'
import { diffLines, Change } from 'diff'
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
import { Textarea } from '@/components/ui/textarea'

interface RestoreDiffModalProps {
  isOpen: boolean
  onClose: () => void
  onConfirm: (reason: string) => void
  currentYaml: string
  targetYaml: string
  targetVersion: number
  currentVersion: number
  isRestoring: boolean
  targetChangeReason?: string
}

export function RestoreDiffModal({
  isOpen,
  onClose,
  onConfirm,
  currentYaml,
  targetYaml,
  targetVersion,
  currentVersion,
  isRestoring,
  targetChangeReason,
}: RestoreDiffModalProps) {
  const [reason, setReason] = useState('')

  const diff = useMemo(() => {
    return diffLines(currentYaml, targetYaml)
  }, [currentYaml, targetYaml])

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

  return (
    <Dialog open={isOpen} onOpenChange={(open) => !open && handleClose()}>
      <DialogContent className="max-w-3xl max-h-[80vh] flex flex-col">
        <DialogHeader>
          <DialogTitle>Restore to Version {targetVersion}</DialogTitle>
          <DialogDescription>
            This will create a new version (v{currentVersion + 1}) with the content from v{targetVersion}.
          </DialogDescription>
        </DialogHeader>

        <div className="flex-1 overflow-auto border rounded-md bg-muted/50 p-4 font-mono text-sm">
          {diff.map((part: Change, index: number) => {
            const lines = part.value.split('\n').filter((_: string, i: number, arr: string[]) =>
              i < arr.length - 1 || arr[i] !== ''
            )

            return lines.map((line: string, lineIndex: number) => {
              let className = ''
              let prefix = ' '

              if (part.added) {
                className = 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-200'
                prefix = '+'
              } else if (part.removed) {
                className = 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-200'
                prefix = '-'
              }

              return (
                <div key={`${index}-${lineIndex}`} className={className}>
                  <span className="select-none text-muted-foreground mr-2">{prefix}</span>
                  {line}
                </div>
              )
            })
          })}
        </div>

        <div className="text-sm text-muted-foreground space-y-2">
          <div>
            Showing changes: v{currentVersion} (current) → v{targetVersion} (restoring to)
          </div>
          {targetChangeReason ? (
            <div className="italic border-l-2 border-primary pl-2 py-1">
              <span className="font-medium">Reason for v{targetVersion}:</span> "{targetChangeReason}"
            </div>
          ) : null}
        </div>

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
