// frontend/src/components/AboutDialog.tsx
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { useVersion } from '@/hooks/use-version'
import { CheckCircle2, AlertCircle, ExternalLink, Loader2 } from 'lucide-react'

interface AboutDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function AboutDialog({ open, onOpenChange }: AboutDialogProps) {
  const { version, updateAvailable, latestVersion, releaseUrl, loading, checkForUpdates } = useVersion()

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>About CHAD</DialogTitle>
        </DialogHeader>

        <div className="space-y-4">
          <div className="text-center py-4">
            <h2 className="text-2xl font-bold">CHAD</h2>
            <p className="text-muted-foreground">Cyber Hunting And Detection</p>
          </div>

          <div className="rounded-lg border p-4 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Version</span>
              <span className="font-mono">{version || 'Unknown'}</span>
            </div>

            {updateAvailable ? (
              <div className="flex items-center gap-2 text-amber-600 dark:text-amber-500">
                <AlertCircle className="h-4 w-4" />
                <span className="text-sm">Update available: {latestVersion}</span>
              </div>
            ) : (
              <div className="flex items-center gap-2 text-green-600 dark:text-green-500">
                <CheckCircle2 className="h-4 w-4" />
                <span className="text-sm">You're on the latest version</span>
              </div>
            )}
          </div>

          <div className="flex flex-col gap-2">
            <Button
              variant="outline"
              onClick={checkForUpdates}
              disabled={loading}
            >
              {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Check for Updates
            </Button>

            {updateAvailable && releaseUrl && (
              <Button asChild>
                <a href={releaseUrl} target="_blank" rel="noopener noreferrer">
                  View Release
                  <ExternalLink className="ml-2 h-4 w-4" />
                </a>
              </Button>
            )}
          </div>

          <div className="border-t pt-4">
            <div className="flex justify-center gap-4 text-sm">
              <a
                href="https://github.com/TerrifiedBug/chad"
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground hover:text-foreground flex items-center gap-1"
              >
                GitHub
                <ExternalLink className="h-3 w-3" />
              </a>
              <a
                href="https://github.com/TerrifiedBug/chad/blob/main/CHANGELOG.md"
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground hover:text-foreground flex items-center gap-1"
              >
                Changelog
                <ExternalLink className="h-3 w-3" />
              </a>
            </div>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}
