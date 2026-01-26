import { useMemo } from 'react'
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

interface RestoreDiffModalProps {
  isOpen: boolean
  onClose: () => void
  onConfirm: () => void
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
  // Debug log props
  if (isOpen) {
    console.log('[RestoreDiffModal] isOpen:', isOpen)
    console.log('[RestoreDiffModal] targetChangeReason:', targetChangeReason)
    console.log('[RestoreDiffModal] targetVersion:', targetVersion, 'type:', typeof targetVersion)
    console.log('[RestoreDiffModal] currentVersion:', currentVersion, 'type:', typeof currentVersion)
    console.log('[RestoreDiffModal] currentYaml type:', typeof currentYaml)
    console.log('[RestoreDiffModal] targetYaml type:', typeof targetYaml)
    console.log('[RestoreDiffModal] targetYaml first 100 chars:', String(targetYaml).substring(0, 100))

    // Check if any props are objects
    if (typeof targetVersion === 'object' && targetVersion !== null) {
      console.log('[RestoreDiffModal] ERROR: targetVersion is an object!', Object.keys(targetVersion))
    }
    if (typeof currentVersion === 'object' && currentVersion !== null) {
      console.log('[RestoreDiffModal] ERROR: currentVersion is an object!', Object.keys(currentVersion))
    }
  }

  const diff = useMemo(() => {
    console.log('[RestoreDiffModal] Computing diff...')
    const result = diffLines(currentYaml, targetYaml)
    console.log('[RestoreDiffModal] Diff result type:', typeof result)
    console.log('[RestoreDiffModal] Diff result is array:', Array.isArray(result))
    console.log('[RestoreDiffModal] Diff length:', result.length)
    if (result.length > 0) {
      console.log('[RestoreDiffModal] First diff part:', result[0])
      console.log('[RestoreDiffModal] First diff part.value type:', typeof result[0].value)
    }
    return result
  }, [currentYaml, targetYaml])

  return (
    <Dialog open={isOpen} onOpenChange={(open) => !open && onClose()}>
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

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={isRestoring}>
            Cancel
          </Button>
          <Button onClick={onConfirm} disabled={isRestoring}>
            {isRestoring ? 'Restoring...' : `Restore to v${targetVersion}`}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
