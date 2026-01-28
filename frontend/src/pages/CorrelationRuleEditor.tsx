import { useEffect, useState, useCallback } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { rulesApi, correlationRulesApi, Rule, FieldMappingInfo } from '@/lib/api'
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
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { ChevronLeft, Loader2, Check, ChevronDown, History } from 'lucide-react'

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
          {selectedRule ? selectedRule.title : placeholder}
          <ChevronDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-[300px] p-0">
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
                  className={`h-4 w-4 ${value === rule.id ? 'opacity-100' : 'opacity-0'}`}
                />
                <span className="flex-1 text-left">{rule.title}</span>
              </button>
            ))
          )}
        </div>
      </PopoverContent>
    </Popover>
  )
}

export default function CorrelationRuleEditorPage() {
  const navigate = useNavigate()
  const { id } = useParams<{ id: string }>()
  const isEditing = Boolean(id)

  const [rules, setRules] = useState<Rule[]>([])
  const [availableFields, setAvailableFields] = useState<string[]>([])
  const [isLoadingFields, setIsLoadingFields] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [isSaving, setIsSaving] = useState(false)
  const [error, setError] = useState('')
  const [isActivityOpen, setIsActivityOpen] = useState(false)
  const [currentVersion, setCurrentVersion] = useState(1)
  const [ruleAFieldMappings, setRuleAFieldMappings] = useState<FieldMappingInfo[]>([])
  const [ruleBFieldMappings, setRuleBFieldMappings] = useState<FieldMappingInfo[]>([])
  const [isLoadingEditData, setIsLoadingEditData] = useState(false) // Track if editing data is loading

  const [formData, setFormData] = useState<{
    name: string
    rule_a_id: string
    rule_b_id: string
    entity_field: string
    time_window_minutes: number
    severity: Severity
    change_reason: string
  }>({
    name: '',
    rule_a_id: '',
    rule_b_id: '',
    entity_field: '',
    time_window_minutes: 5,
    severity: 'high',
    change_reason: '',
  })

  // Load functions - must be declared before useEffect that uses them
  async function loadRuleFields(ruleId: string): Promise<{ fields: string[], mappings: FieldMappingInfo[] }> {
    try {
      const rule = await rulesApi.get(ruleId)
      // Use validation API to get detected fields (same as RuleEditor)
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
    // Use passed IDs or fall back to formData (for new rule creation where IDs are set via UI)
    const actualRuleAId = ruleAId || formData.rule_a_id
    const actualRuleBId = ruleBId || formData.rule_b_id

    if (!actualRuleAId || !actualRuleBId) {
      return
    }

    setIsLoadingFields(true)
    try {
      // Load fields for both rules in parallel using validation API
      const [resultA, resultB] = await Promise.all([
        loadRuleFields(actualRuleAId),
        loadRuleFields(actualRuleBId),
      ])

      // Find common fields
      const commonFields = resultA.fields.filter((field) =>
        resultB.fields.includes(field)
      )

      setAvailableFields(commonFields)
      setRuleAFieldMappings(resultA.mappings)
      setRuleBFieldMappings(resultB.mappings)

      // Auto-select entity field if:
      // 1. We're editing (id exists) and currentEntityField is provided
      // 2. The currentEntityField is in the common fields
      // 3. No entity field is currently selected in formData
      if (currentEntityField && commonFields.includes(currentEntityField) && !formData.entity_field) {
        setFormData((prev) => ({ ...prev, entity_field: currentEntityField }))
      }
      // If current entity_field is no longer in common fields, clear it
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
      const response = await rulesApi.list({ status: 'deployed' })
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
      setFormData({
        name: rule.name,
        rule_a_id: rule.rule_a_id,
        rule_b_id: rule.rule_b_id,
        entity_field: rule.entity_field,
        time_window_minutes: rule.time_window_minutes,
        severity: rule.severity,
        change_reason: '',
      })
      setCurrentVersion(rule.current_version)
      // Load common fields with the current entity_field to ensure it's in the list
      // Pass the IDs directly to avoid race condition with formData state updates
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

  // Load Sigma fields when both rules are selected (only for NEW rules, not editing)
  useEffect(() => {
    // Skip entirely if editing or loading edit data
    if (id || isLoadingEditData) return

    // Only proceed if both rules are selected for a NEW rule
    if (formData.rule_a_id && formData.rule_b_id) {
      loadCommonFields(formData.entity_field)
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [formData.rule_a_id, formData.rule_b_id, id, isLoadingEditData, formData.entity_field])

  // Clear fields when switching from editing to creating
  useEffect(() => {
    if (!id && !isLoadingEditData) {
      setAvailableFields([])
      setRuleAFieldMappings([])
      setRuleBFieldMappings([])
    }
  }, [id, isLoadingEditData])

  // Helper function to get target field from mappings
  const getTargetField = (sigmaField: string, mappings: FieldMappingInfo[]): string | undefined => {
    const mapping = mappings.find(m => m.sigma_field === sigmaField)
    return mapping?.target_field ?? undefined
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setIsSaving(true)

    try {
      if (isEditing && id) {
        await correlationRulesApi.update(id, formData)
      } else {
        await correlationRulesApi.create(formData)
      }
      navigate('/correlation')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save correlation rule')
      setIsSaving(false)
    }
  }

  // Show loading state while editing data is being fetched
  if (isLoading) {
    return (
      <div className="space-y-6 max-w-2xl">
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

  const formContent = (
    <>
      {error && (
        <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md">
          {error}
        </div>
      )}

      <div className="space-y-2">
        <Label htmlFor="name">Name</Label>
        <Input
          id="name"
          placeholder="e.g., Brute Force Success"
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          required
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="rule_a">First Rule (Rule A)</Label>
        <SearchableRuleSelector
          rules={rules}
          value={formData.rule_a_id}
          onChange={(value) => setFormData({ ...formData, rule_a_id: value })}
          disabled={isLoading || isSaving}
          placeholder="Select first rule"
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="rule_b">Second Rule (Rule B)</Label>
        <SearchableRuleSelector
          rules={rules}
          value={formData.rule_b_id}
          onChange={(value) => setFormData({ ...formData, rule_b_id: value })}
          disabled={isLoading || isSaving}
          placeholder="Select second rule"
          excludeRuleId={formData.rule_a_id}
        />
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

      <div className="space-y-2">
        <Label htmlFor="change_reason">Change Reason *</Label>
        <Textarea
          id="change_reason"
          placeholder={isEditing ? "e.g., Updated time window, fixed entity field..." : "e.g., Initial creation, detecting brute force patterns..."}
          value={formData.change_reason}
          onChange={(e) => setFormData({ ...formData, change_reason: e.target.value })}
          rows={3}
          className="resize-none"
          required
        />
        <p className="text-xs text-muted-foreground">
          Explain why you're {isEditing ? 'updating' : 'creating'} this rule. This helps maintain an audit trail.
        </p>
      </div>

      <div className="flex gap-2 pt-4">
        <Button
          type="button"
          variant="outline"
          onClick={() => navigate('/correlation')}
          disabled={isSaving}
        >
          Cancel
        </Button>
        <Button type="submit" disabled={isSaving || isLoading || !formData.name || !formData.rule_a_id || !formData.rule_b_id || !formData.change_reason.trim()}>
          {isSaving && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
          {isEditing ? 'Update' : 'Create'} Rule
        </Button>
      </div>
    </>
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={() => navigate('/correlation')}>
            <ChevronLeft className="h-4 w-4" />
          </Button>
          <div>
            <h1 className="text-2xl font-bold">
              {isEditing ? 'Edit Correlation Rule' : 'Create Correlation Rule'}
            </h1>
            <p className="text-sm text-muted-foreground">
              {isEditing
                ? 'Modify the correlation rule configuration'
                : 'Define when two rules together indicate a higher-priority pattern'}
            </p>
          </div>
        </div>
        {isEditing && (
          <Button variant="outline" onClick={() => setIsActivityOpen(true)}>
            <History className="h-4 w-4 mr-2" />
            Activity
          </Button>
        )}
      </div>

      <Card className="max-w-2xl">
        <CardHeader>
          <CardTitle>Rule Configuration</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            {formContent}
          </form>
        </CardContent>
      </Card>

      {/* Activity Panel (slide-out) */}
      {isEditing && id && (
        <CorrelationActivityPanel
          correlationId={id}
          currentVersion={currentVersion}
          isOpen={isActivityOpen}
          onClose={() => setIsActivityOpen(false)}
        />
      )}
    </div>
  )
}
