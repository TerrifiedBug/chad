import { useEffect, useState, useCallback } from 'react'
import { useNavigate, useParams, useLocation } from 'react-router-dom'
import { rulesApi, correlationRulesApi, Rule, FieldMappingInfo, CorrelationRule } from '@/lib/api'
import { useToast } from '@/components/ui/toast-provider'
import type { Severity } from '@/types/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { CorrelationActivityPanel } from '@/components/CorrelationActivityPanel'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { ChevronLeft, Loader2, Check, ChevronDown, History, Rocket, RotateCcw, AlertCircle, Copy, Trash2 } from 'lucide-react'

const TIME_WINDOW_OPTIONS = [
  { value: 1, label: '1 minute' },
  { value: 5, label: '5 minutes' },
  { value: 15, label: '15 minutes' },
  { value: 30, label: '30 minutes' },
  { value: 60, label: '1 hour' },
  { value: 120, label: '2 hours' },
  { value: 240, label: '4 hours' },
  { value: 480, label: '8 hours' },
  { value: 1440, label: '24 hours' },
]

const SEVERITY_OPTIONS = [
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'informational', label: 'Informational' },
]

// Status badge helper
function RuleStatusBadge({ status }: { status: string }) {
  if (status === 'deployed') {
    return (
      <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-green-600 text-white">
        Deployed
      </span>
    )
  }
  if (status === 'snoozed') {
    return (
      <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-yellow-500 text-white">
        Snoozed
      </span>
    )
  }
  return (
    <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-gray-500 text-white">
      Undeployed
    </span>
  )
}

// Searchable Rule Selector Component
function SearchableRuleSelector({
  rules,
  value,
  onChange,
  disabled,
  placeholder,
  excludeRuleId,
}: {
  rules: Rule[]
  value: string
  onChange: (value: string) => void
  disabled?: boolean
  placeholder: string
  excludeRuleId?: string
}) {
  const [open, setOpen] = useState(false)
  const [search, setSearch] = useState('')

  const filteredRules = rules.filter(
    (rule) =>
      rule.id !== excludeRuleId &&
      rule.title.toLowerCase().includes(search.toLowerCase())
  )

  const selectedRule = rules.find((r) => r.id === value)

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          role="combobox"
          aria-expanded={open}
          disabled={disabled}
          className="w-full justify-between"
        >
          <div className="flex items-center gap-2 truncate">
            {selectedRule ? (
              <>
                <span className="truncate">{selectedRule.title}</span>
                <RuleStatusBadge status={selectedRule.status} />
              </>
            ) : (
              placeholder
            )}
          </div>
          <ChevronDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-[400px] p-0">
        <div className="p-2">
          <Input
            placeholder="Search rules..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="h-9"
            autoFocus
          />
        </div>
        <div className="max-h-[300px] overflow-y-auto">
          {filteredRules.length === 0 ? (
            <div className="p-2 text-sm text-muted-foreground text-center">
              {search ? 'No matching rules found' : 'No rules available'}
            </div>
          ) : (
            filteredRules.map((rule) => (
              <button
                key={rule.id}
                onClick={() => {
                  onChange(rule.id)
                  setOpen(false)
                  setSearch('')
                }}
                className="w-full flex items-center gap-2 px-3 py-2 text-sm hover:bg-accent hover:text-accent-foreground cursor-pointer"
              >
                <Check
                  className={`h-4 w-4 shrink-0 ${value === rule.id ? 'opacity-100' : 'opacity-0'}`}
                />
                <span className="flex-1 text-left truncate">{rule.title}</span>
                <RuleStatusBadge status={rule.status} />
              </button>
            ))
          )}
        </div>
      </PopoverContent>
    </Popover>
  )
}

interface CloneFromState {
  name: string
  rule_a_id: string
  rule_b_id: string
  entity_field: string
  time_window_minutes: number
  severity: Severity
}

export default function CorrelationRuleEditorPage() {
  const navigate = useNavigate()
  const location = useLocation()
  const { id } = useParams<{ id: string }>()
  const isEditing = Boolean(id)
  const { showToast } = useToast()

  // Check for clone data from location state
  const cloneFrom = (location.state as { cloneFrom?: CloneFromState } | null)?.cloneFrom

  const [rules, setRules] = useState<Rule[]>([])
  const [availableFields, setAvailableFields] = useState<string[]>([])
  const [isLoadingFields, setIsLoadingFields] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [isSaving, setIsSaving] = useState(false)
  const [isDeploying, setIsDeploying] = useState(false)
  const [error, setError] = useState('')
  const [saveSuccess, setSaveSuccess] = useState(false)
  const [isActivityOpen, setIsActivityOpen] = useState(false)
  const [correlationRule, setCorrelationRule] = useState<CorrelationRule | null>(null)
  const [ruleAFieldMappings, setRuleAFieldMappings] = useState<FieldMappingInfo[]>([])
  const [ruleBFieldMappings, setRuleBFieldMappings] = useState<FieldMappingInfo[]>([])
  const [isLoadingEditData, setIsLoadingEditData] = useState(false)

  // Dialog states
  const [showChangeReason, setShowChangeReason] = useState(false)
  const [changeReason, setChangeReason] = useState('')
  const [showDeployReason, setShowDeployReason] = useState(false)
  const [showUndeployReason, setShowUndeployReason] = useState(false)
  const [deployReason, setDeployReason] = useState('')

  // Track original values for change detection
  const [originalData, setOriginalData] = useState<typeof formData | null>(null)

  const [formData, setFormData] = useState<{
    name: string
    rule_a_id: string
    rule_b_id: string
    entity_field: string
    time_window_minutes: number
    severity: Severity
  }>(cloneFrom ?? {
    name: '',
    rule_a_id: '',
    rule_b_id: '',
    entity_field: '',
    time_window_minutes: 5,
    severity: 'high',
  })

  // Check if form has changes
  const hasChanges = useCallback(() => {
    if (!originalData) return false
    return (
      formData.name !== originalData.name ||
      formData.rule_a_id !== originalData.rule_a_id ||
      formData.rule_b_id !== originalData.rule_b_id ||
      formData.entity_field !== originalData.entity_field ||
      formData.time_window_minutes !== originalData.time_window_minutes ||
      formData.severity !== originalData.severity
    )
  }, [formData, originalData])

  // Check if linked rules are deployed
  const linkedRulesDeploymentStatus = (() => {
    const ruleA = rules.find(r => r.id === formData.rule_a_id)
    const ruleB = rules.find(r => r.id === formData.rule_b_id)
    const undeployedRules: string[] = []

    if (ruleA && ruleA.status !== 'deployed') {
      undeployedRules.push(ruleA.title)
    }
    if (ruleB && ruleB.status !== 'deployed') {
      undeployedRules.push(ruleB.title)
    }

    return {
      allDeployed: undeployedRules.length === 0,
      undeployedNames: undeployedRules,
    }
  })()

  // Load functions
  async function loadRuleFields(ruleId: string): Promise<{ fields: string[], mappings: FieldMappingInfo[] }> {
    try {
      const rule = await rulesApi.get(ruleId)
      const result = await rulesApi.validate(rule.yaml_content, rule.index_pattern_id)
      return {
        fields: result.fields || [],
        mappings: result.field_mappings || [],
      }
    } catch (err) {
      console.error('Failed to load rule fields:', err)
      return { fields: [], mappings: [] }
    }
  }

  const loadCommonFields = useCallback(async (currentEntityField?: string, ruleAId?: string, ruleBId?: string) => {
    const actualRuleAId = ruleAId || formData.rule_a_id
    const actualRuleBId = ruleBId || formData.rule_b_id

    if (!actualRuleAId || !actualRuleBId) {
      return
    }

    setIsLoadingFields(true)
    try {
      const [resultA, resultB] = await Promise.all([
        loadRuleFields(actualRuleAId),
        loadRuleFields(actualRuleBId),
      ])

      const commonFields = resultA.fields.filter((field) =>
        resultB.fields.includes(field)
      )

      setAvailableFields(commonFields)
      setRuleAFieldMappings(resultA.mappings)
      setRuleBFieldMappings(resultB.mappings)

      if (currentEntityField && commonFields.includes(currentEntityField) && !formData.entity_field) {
        setFormData((prev) => ({ ...prev, entity_field: currentEntityField }))
      }
      if (formData.entity_field && !commonFields.includes(formData.entity_field)) {
        setFormData((prev) => ({ ...prev, entity_field: '' }))
      }
    } catch (err) {
      console.error('Failed to load common fields:', err)
      setAvailableFields([])
    } finally {
      setIsLoadingFields(false)
    }
  }, [formData.rule_a_id, formData.rule_b_id, formData.entity_field])

  const loadRules = async () => {
    setIsLoading(true)
    try {
      // Load all rules (not just deployed) so we can show status badges
      // and properly validate that linked rules are deployed before deployment
      const response = await rulesApi.list({})
      setRules(response)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load rules')
    } finally {
      setIsLoading(false)
    }
  }

  const loadRule = useCallback(async (ruleId: string) => {
    setIsLoadingEditData(true)
    setIsLoading(true)
    try {
      const rule = await correlationRulesApi.get(ruleId)
      const data = {
        name: rule.name,
        rule_a_id: rule.rule_a_id,
        rule_b_id: rule.rule_b_id,
        entity_field: rule.entity_field,
        time_window_minutes: rule.time_window_minutes,
        severity: rule.severity,
      }
      setFormData(data)
      setOriginalData(data)
      setCorrelationRule(rule)
      await loadCommonFields(rule.entity_field, rule.rule_a_id, rule.rule_b_id)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load correlation rule')
    } finally {
      setIsLoadingEditData(false)
      setIsLoading(false)
    }
  }, [loadCommonFields])

  useEffect(() => {
    loadRules()
    if (id) loadRule(id)
  }, [id, loadRule])

  useEffect(() => {
    if (id || isLoadingEditData) return
    if (formData.rule_a_id && formData.rule_b_id) {
      loadCommonFields(formData.entity_field)
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [formData.rule_a_id, formData.rule_b_id, id, isLoadingEditData, formData.entity_field])

  useEffect(() => {
    if (!id && !isLoadingEditData) {
      setAvailableFields([])
      setRuleAFieldMappings([])
      setRuleBFieldMappings([])
    }
  }, [id, isLoadingEditData])

  const getTargetField = (sigmaField: string, mappings: FieldMappingInfo[]): string | undefined => {
    const mapping = mappings.find(m => m.sigma_field === sigmaField)
    return mapping?.target_field ?? undefined
  }

  const isFormValid = formData.name && formData.rule_a_id && formData.rule_b_id && formData.entity_field

  // Handle Save button click
  const handleSave = () => {
    if (!isFormValid) {
      setError('Please fill in all required fields')
      return
    }

    if (isEditing && !changeReason.trim()) {
      setShowChangeReason(true)
      return
    }

    performSave()
  }

  // Actually perform the save
  const performSave = async () => {
    setError('')
    setIsSaving(true)
    setSaveSuccess(false)

    try {
      if (isEditing && id) {
        await correlationRulesApi.update(id, {
          ...formData,
          change_reason: changeReason || 'Updated',
        })
        await loadRule(id)
        setSaveSuccess(true)
        setChangeReason('')
        setShowChangeReason(false)
        setTimeout(() => setSaveSuccess(false), 3000)
      } else {
        await correlationRulesApi.create({
          ...formData,
          change_reason: changeReason || 'Initial creation',
        })
        navigate('/correlation')
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save correlation rule')
    } finally {
      setIsSaving(false)
    }
  }

  // Deploy handlers
  const handleDeploy = () => {
    if (!id) return
    setDeployReason('')
    setShowDeployReason(true)
  }

  const handleDeployConfirm = async () => {
    if (!id) return
    setShowDeployReason(false)
    setIsDeploying(true)
    setError('')

    try {
      const result = await correlationRulesApi.deploy(id, deployReason)
      setCorrelationRule(result)
      setDeployReason('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Deploy failed')
    } finally {
      setIsDeploying(false)
    }
  }

  const handleUndeploy = () => {
    if (!id) return
    setDeployReason('')
    setShowUndeployReason(true)
  }

  const handleUndeployConfirm = async () => {
    if (!id) return
    setShowUndeployReason(false)
    setIsDeploying(true)
    setError('')

    try {
      const result = await correlationRulesApi.undeploy(id, deployReason)
      setCorrelationRule(result)
      setDeployReason('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Undeploy failed')
    } finally {
      setIsDeploying(false)
    }
  }

  // Restore handler for version rollback
  const handleRestore = async (versionNumber: number, reason: string) => {
    if (!id) return
    try {
      await correlationRulesApi.rollback(id, versionNumber, reason)
      // Reload the rule to get updated data
      const updated = await correlationRulesApi.get(id)
      setCorrelationRule(updated)
      // Update form data
      setFormData({
        name: updated.name,
        rule_a_id: updated.rule_a_id,
        rule_b_id: updated.rule_b_id,
        entity_field: updated.entity_field,
        time_window_minutes: updated.time_window_minutes,
        severity: updated.severity,
      })
      setOriginalData({
        name: updated.name,
        rule_a_id: updated.rule_a_id,
        rule_b_id: updated.rule_b_id,
        entity_field: updated.entity_field,
        time_window_minutes: updated.time_window_minutes,
        severity: updated.severity,
      })
      showToast(`Restored to version ${versionNumber}`, 'success')
    } catch (err) {
      showToast('Failed to restore version', 'error')
      throw err
    }
  }

  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)
  const [isDeleting, setIsDeleting] = useState(false)

  const handleClone = () => {
    // Navigate to create form with pre-populated values
    navigate('/correlation/new', {
      state: {
        cloneFrom: {
          name: `${formData.name} (Copy)`,
          rule_a_id: formData.rule_a_id,
          rule_b_id: formData.rule_b_id,
          entity_field: formData.entity_field,
          time_window_minutes: formData.time_window_minutes,
          severity: formData.severity,
        }
      }
    })
    showToast('Edit the cloned rule and save when ready', 'info')
  }

  const handleDelete = async () => {
    if (!id) return
    setIsDeleting(true)
    try {
      await correlationRulesApi.delete(id)
      showToast('Correlation rule deleted', 'success')
      navigate('/correlation')
    } catch (err) {
      showToast('Failed to delete correlation rule', 'error')
    } finally {
      setIsDeleting(false)
      setShowDeleteConfirm(false)
    }
  }

  // Loading state
  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={() => navigate('/correlation')}>
            <ChevronLeft className="h-4 w-4" />
          </Button>
          <div>
            <h1 className="text-2xl font-bold">
              {isEditing ? 'Edit Correlation Rule' : 'Create Correlation Rule'}
            </h1>
          </div>
        </div>
        <Card>
          <CardContent className="flex items-center justify-center py-12">
            <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header with actions */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={() => navigate('/correlation')}>
            <ChevronLeft className="h-4 w-4" />
          </Button>
          <div>
            <h1 className="text-2xl font-bold">
              {isEditing ? 'Edit Correlation Rule' : 'Create Correlation Rule'}
            </h1>
            {isEditing && correlationRule?.deployed_at && (
              <p className={`text-xs ${correlationRule?.needs_redeploy ? 'text-yellow-600' : 'text-green-600'}`}>
                {correlationRule?.needs_redeploy
                  ? `Deployed v${correlationRule.deployed_version} (current is v${correlationRule.current_version} - redeploy needed)`
                  : `Deployed v${correlationRule.deployed_version}`
                }
              </p>
            )}
            {isEditing && !correlationRule?.deployed_at && (
              <p className="text-xs text-muted-foreground">Not deployed</p>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2">
          {saveSuccess && (
            <span className="text-sm text-green-600 flex items-center gap-1 mr-2">
              <Check className="h-4 w-4" />
              Saved
            </span>
          )}
          {isEditing && (
            <Button variant="outline" onClick={() => setIsActivityOpen(true)}>
              <History className="h-4 w-4 mr-2" />
              Activity
            </Button>
          )}
          {isEditing && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline">
                  More Actions <ChevronDown className="ml-2 h-4 w-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent className="z-50 bg-popover">
                <DropdownMenuItem onClick={handleClone}>
                  <Copy className="mr-2 h-4 w-4" /> Clone Rule
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  onClick={() => setShowDeleteConfirm(true)}
                  className="text-destructive focus:text-destructive"
                >
                  <Trash2 className="mr-2 h-4 w-4" /> Delete Rule
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          )}
          {isEditing && correlationRule?.deployed_at && correlationRule?.needs_redeploy && (
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <span>
                    <Button
                      variant="outline"
                      onClick={handleDeploy}
                      disabled={isDeploying || !linkedRulesDeploymentStatus.allDeployed}
                    >
                      <Rocket className="h-4 w-4 mr-2" />
                      {isDeploying ? 'Redeploying...' : 'Redeploy'}
                    </Button>
                  </span>
                </TooltipTrigger>
                {!linkedRulesDeploymentStatus.allDeployed && (
                  <TooltipContent>
                    <p>Linked rules must be deployed first:</p>
                    <ul className="list-disc ml-4">
                      {linkedRulesDeploymentStatus.undeployedNames.map(name => (
                        <li key={name}>{name}</li>
                      ))}
                    </ul>
                  </TooltipContent>
                )}
              </Tooltip>
            </TooltipProvider>
          )}
          {isEditing && correlationRule?.deployed_at && (
            <Button
              variant="ghost"
              onClick={handleUndeploy}
              disabled={isDeploying}
            >
              <RotateCcw className="h-4 w-4 mr-2" />
              {isDeploying ? 'Undeploying...' : 'Undeploy'}
            </Button>
          )}
          {isEditing && !correlationRule?.deployed_at && (
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <span>
                    <Button
                      variant="outline"
                      onClick={handleDeploy}
                      disabled={isDeploying || !isFormValid || !linkedRulesDeploymentStatus.allDeployed}
                    >
                      <Rocket className="h-4 w-4 mr-2" />
                      {isDeploying ? 'Deploying...' : 'Deploy'}
                    </Button>
                  </span>
                </TooltipTrigger>
                {!linkedRulesDeploymentStatus.allDeployed && (
                  <TooltipContent>
                    <p>Linked rules must be deployed first:</p>
                    <ul className="list-disc ml-4">
                      {linkedRulesDeploymentStatus.undeployedNames.map(name => (
                        <li key={name}>{name}</li>
                      ))}
                    </ul>
                  </TooltipContent>
                )}
              </Tooltip>
            </TooltipProvider>
          )}
          <Button
            onClick={handleSave}
            disabled={isSaving || !isFormValid || (isEditing && !hasChanges())}
          >
            {isSaving ? 'Saving...' : 'Save'}
          </Button>
        </div>
      </div>

      {error && (
        <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md">
          {error}
        </div>
      )}

      {isEditing && correlationRule?.deployed_at && correlationRule?.needs_redeploy && (
        <div className="bg-orange-500/10 text-orange-600 text-sm p-3 rounded-md flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertCircle className="h-4 w-4" />
            This correlation rule has been modified since deployment. Redeploy to apply changes.
          </div>
          <Button
            size="sm"
            onClick={handleDeploy}
            disabled={isDeploying || !linkedRulesDeploymentStatus.allDeployed}
          >
            {isDeploying ? 'Redeploying...' : 'Redeploy Now'}
          </Button>
        </div>
      )}

      {/* Form */}
      <Card>
        <CardHeader>
          <CardTitle>Rule Configuration</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="name">Name</Label>
            <Input
              id="name"
              placeholder="e.g., Brute Force Success"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="rule_a">First Rule (Rule A)</Label>
              <SearchableRuleSelector
                rules={rules}
                value={formData.rule_a_id}
                onChange={(value) => setFormData({ ...formData, rule_a_id: value })}
                disabled={isSaving}
                placeholder="Select first rule"
                excludeRuleId={formData.rule_b_id}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="rule_b">Second Rule (Rule B)</Label>
              <SearchableRuleSelector
                rules={rules}
                value={formData.rule_b_id}
                onChange={(value) => setFormData({ ...formData, rule_b_id: value })}
                disabled={isSaving}
                placeholder="Select second rule"
                excludeRuleId={formData.rule_a_id}
              />
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="entity_field">Entity Field to Correlate</Label>
            <Select
              value={formData.entity_field}
              onValueChange={(value) => setFormData({ ...formData, entity_field: value })}
              disabled={isSaving || isLoadingFields || !formData.rule_a_id}
            >
              <SelectTrigger data-protonpass-ignore="true" data-lpignore="true" data-1p-ignore="true">
                <SelectValue placeholder={isLoadingFields ? "Loading fields..." : "Select entity field"} />
              </SelectTrigger>
              <SelectContent className="z-50 bg-popover max-h-[300px]">
                {availableFields.length === 0 ? (
                  <div className="p-2 text-sm text-muted-foreground">
                    {formData.rule_a_id
                      ? "No common fields found between the two rules."
                      : "Select both rules to load common fields"}
                  </div>
                ) : (
                  availableFields.map((field) => (
                    <SelectItem key={field} value={field}>
                      {field}
                    </SelectItem>
                  ))
                )}
              </SelectContent>
            </Select>
            {formData.entity_field && (
              <div className="text-xs text-muted-foreground bg-muted/50 p-2 rounded">
                <div className="font-medium mb-1">Field Mappings:</div>
                <div>Rule A: <span className="font-mono">{formData.entity_field}</span> → <span className="font-mono">{getTargetField(formData.entity_field, ruleAFieldMappings) || <span className="text-destructive">Not mapped</span>}</span></div>
                <div>Rule B: <span className="font-mono">{formData.entity_field}</span> → <span className="font-mono">{getTargetField(formData.entity_field, ruleBFieldMappings) || <span className="text-destructive">Not mapped</span>}</span></div>
              </div>
            )}
            <p className="text-xs text-muted-foreground">
              The Sigma field name from both rules used to correlate events. This field must be detected by both rules.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="time_window">Time Window</Label>
              <Select
                value={String(formData.time_window_minutes)}
                onValueChange={(value) => setFormData({ ...formData, time_window_minutes: Number(value) })}
                disabled={isSaving}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="z-50 bg-popover">
                  {TIME_WINDOW_OPTIONS.map((option) => (
                    <SelectItem key={option.value} value={String(option.value)}>
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                Maximum time allowed between Rule A and Rule B matches
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="severity">Severity</Label>
              <Select
                value={formData.severity}
                onValueChange={(value) => setFormData({ ...formData, severity: value as Severity })}
                disabled={isSaving}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="z-50 bg-popover">
                  {SEVERITY_OPTIONS.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Activity Panel (slide-out) */}
      {isEditing && id && (
        <CorrelationActivityPanel
          correlationId={id}
          isOpen={isActivityOpen}
          onClose={() => setIsActivityOpen(false)}
          currentVersion={correlationRule?.current_version || 1}
          currentData={{
            name: formData.name,
            rule_a_id: formData.rule_a_id,
            rule_b_id: formData.rule_b_id,
            entity_field: formData.entity_field,
            time_window_minutes: formData.time_window_minutes,
            severity: formData.severity,
          }}
          onRestore={handleRestore}
        />
      )}

      {/* Change Reason Modal */}
      <Dialog open={showChangeReason} onOpenChange={setShowChangeReason}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Change Reason Required</DialogTitle>
            <DialogDescription>
              Please explain why you're updating this rule. This helps maintain an audit trail.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="change-reason">Reason for Change *</Label>
              <Textarea
                id="change-reason"
                placeholder="Explain why you're making this change..."
                value={changeReason}
                onChange={(e) => setChangeReason(e.target.value)}
                rows={4}
                className="resize-none"
              />
            </div>
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setShowChangeReason(false)
                setChangeReason('')
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={performSave}
              disabled={!changeReason.trim() || isSaving}
            >
              {isSaving ? 'Saving...' : 'Save with Reason'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Deploy Reason Modal */}
      <Dialog open={showDeployReason} onOpenChange={setShowDeployReason}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Deploy Correlation Rule</DialogTitle>
            <DialogDescription>
              Please explain why you're deploying this rule. This helps maintain an audit trail.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="deploy-reason">Reason for Deploy *</Label>
              <Textarea
                id="deploy-reason"
                placeholder="e.g., Ready for production, completed testing..."
                value={deployReason}
                onChange={(e) => setDeployReason(e.target.value)}
                rows={3}
                className="resize-none"
              />
            </div>
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setShowDeployReason(false)
                setDeployReason('')
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={handleDeployConfirm}
              disabled={!deployReason.trim() || isDeploying}
            >
              {isDeploying ? 'Deploying...' : 'Deploy'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Undeploy Reason Modal */}
      <Dialog open={showUndeployReason} onOpenChange={setShowUndeployReason}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Undeploy Correlation Rule</DialogTitle>
            <DialogDescription>
              Please explain why you're undeploying this rule. This helps maintain an audit trail.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="undeploy-reason">Reason for Undeploy *</Label>
              <Textarea
                id="undeploy-reason"
                placeholder="e.g., False positives, needs revision, no longer needed..."
                value={deployReason}
                onChange={(e) => setDeployReason(e.target.value)}
                rows={3}
                className="resize-none"
              />
            </div>
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setShowUndeployReason(false)
                setDeployReason('')
              }}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleUndeployConfirm}
              disabled={!deployReason.trim() || isDeploying}
            >
              {isDeploying ? 'Undeploying...' : 'Undeploy'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Modal */}
      <Dialog open={showDeleteConfirm} onOpenChange={setShowDeleteConfirm}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Correlation Rule</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete this correlation rule? This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setShowDeleteConfirm(false)}
              disabled={isDeleting}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleDelete}
              disabled={isDeleting}
            >
              {isDeleting ? 'Deleting...' : 'Delete'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
