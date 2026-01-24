import { useState, useEffect } from 'react'
import { webhooksApi, notificationsApi, Webhook, WebhookProvider, NotificationSettings } from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Checkbox } from '@/components/ui/checkbox'
import { Badge } from '@/components/ui/badge'
import {
  Card,
  CardContent,
  CardHeader,
} from '@/components/ui/card'
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
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible'
import { DeleteConfirmModal } from '@/components/DeleteConfirmModal'
import {
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Loader2,
  Pencil,
  Plus,
  Send,
  Trash2,
} from 'lucide-react'

// System event configuration with grouping
const SYSTEM_EVENT_GROUPS = [
  {
    name: 'Security',
    events: [
      { id: 'user_locked', label: 'User Account Locked' },
    ],
  },
  {
    name: 'Sync Events',
    events: [
      { id: 'sigmahq_sync_complete', label: 'SigmaHQ Sync Complete' },
      { id: 'attack_sync_complete', label: 'ATT&CK Sync Complete' },
      { id: 'sigmahq_new_rules', label: 'New Rules Available' },
      { id: 'sync_failed', label: 'Sync Failed' },
    ],
  },
  {
    name: 'Health Alerts',
    events: [
      { id: 'health_warning', label: 'Health Warning' },
      { id: 'health_critical', label: 'Health Critical' },
    ],
  },
]

// Alert severities
const ALERT_SEVERITIES = [
  { id: 'critical', label: 'Critical', color: 'bg-red-500' },
  { id: 'high', label: 'High', color: 'bg-orange-500' },
  { id: 'medium', label: 'Medium', color: 'bg-yellow-500' },
  { id: 'low', label: 'Low', color: 'bg-blue-500' },
  { id: 'informational', label: 'Info', color: 'bg-gray-500' },
]

const providerLabels: Record<WebhookProvider, string> = {
  generic: 'Generic',
  discord: 'Discord',
  slack: 'Slack',
}

type WebhookFormData = {
  name: string
  url: string
  auth_header: string
  provider: WebhookProvider
  enabled: boolean
}

const emptyFormData: WebhookFormData = {
  name: '',
  url: '',
  auth_header: '',
  provider: 'generic',
  enabled: true,
}

export default function Notifications() {
  const { showToast } = useToast()
  const [isLoading, setIsLoading] = useState(true)
  const [webhooks, setWebhooks] = useState<Webhook[]>([])
  const [settings, setSettings] = useState<NotificationSettings | null>(null)

  // Track which webhooks are expanded
  const [expandedWebhooks, setExpandedWebhooks] = useState<Set<string>>(new Set())

  // Dialog states
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editingWebhook, setEditingWebhook] = useState<Webhook | null>(null)
  const [formData, setFormData] = useState<WebhookFormData>(emptyFormData)
  const [isSaving, setIsSaving] = useState(false)

  // Delete modal state
  const [deleteModalOpen, setDeleteModalOpen] = useState(false)
  const [webhookToDelete, setWebhookToDelete] = useState<Webhook | null>(null)
  const [isDeleting, setIsDeleting] = useState(false)

  // Test state
  const [testingId, setTestingId] = useState<string | null>(null)

  // Saving notification settings
  const [savingSystem, setSavingSystem] = useState<string | null>(null)
  const [savingAlert, setSavingAlert] = useState<string | null>(null)

  useEffect(() => {
    loadData()
  }, [])

  const loadData = async () => {
    try {
      const [webhooksData, notificationData] = await Promise.all([
        webhooksApi.list(),
        notificationsApi.get(),
      ])
      setWebhooks(webhooksData)
      setSettings(notificationData)
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to load data', 'error')
    } finally {
      setIsLoading(false)
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">Notifications</h2>
          <p className="text-sm text-muted-foreground">
            Configure webhook endpoints and what notifications they receive
          </p>
        </div>
        <Button onClick={() => { setEditingWebhook(null); setFormData(emptyFormData); setDialogOpen(true) }}>
          <Plus className="mr-2 h-4 w-4" />
          Add Webhook
        </Button>
      </div>

      {/* Placeholder - webhook cards will be added in Task 3 */}
      <p className="text-muted-foreground">Webhook cards will go here</p>
    </div>
  )
}
