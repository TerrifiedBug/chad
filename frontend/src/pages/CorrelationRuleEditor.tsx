import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { rulesApi, correlationRulesApi, Rule, FieldMappingInfo } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
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
import { ChevronLeft, Loader2, Check, ChevronDown } from 'lucide-react'

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
  const [ruleAFieldMappings, setRuleAFieldMappings] = useState<FieldMappingInfo[]>([])
  const [ruleBFieldMappings, setRuleBFieldMappings] = useState<FieldMappingInfo[]>([])

  const [formData, setFormData] = useState({
    name: '',
    rule_a_id: '',
    rule_b_id: '',
    entity_field: '',
    time_window_minutes: 5,
    severity: 'high' as const,
    is_enabled: true,
  })

  useEffect(() => {
    loadRules()
    if (id) loadRule(id)
  }, [id])

  // Load Sigma fields when both rules are selected
  useEffect(() => {
    if (formData.rule_a_id && formData.rule_b_id) {
      loadCommonFields(formData.entity_field)
    } else {
      setAvailableFields([])
      setRuleAFieldMappings([])
      setRuleBFieldMappings([])
    }
  }, [formData.rule_a_id, formData.rule_b_id])

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

  async function loadCommonFields(currentEntityField?: string) {
    setIsLoadingFields(true)
    try {
      // Load fields for both rules in parallel using validation API
      const [resultA, resultB] = await Promise.all([
        loadRuleFields(formData.rule_a_id!),
        loadRuleFields(formData.rule_b_id!),
      ])

      setRuleAFieldMappings(resultA.mappings)
      setRuleBFieldMappings(resultB.mappings)

      // Find intersection of fields (fields common to both rules)
      let commonFields = resultA.fields.filter(field => resultB.fields.includes(field))

      // When editing, ensure the currently selected field is included in the list
      // This handles cases where the field was removed from one rule but we want to keep it
      if (currentEntityField && !commonFields.includes(currentEntityField)) {
        commonFields = [...commonFields, currentEntityField]
      }

      setAvailableFields(commonFields)
    } catch (err) {
      console.error('Failed to load common fields:', err)
      setAvailableFields([])
    } finally {
      setIsLoadingFields(false)
    }
  }

  // Helper to get target field for a Sigma field from mappings
  function getTargetField(sigmaField: string, mappings: FieldMappingInfo[]): string | null {
    const mapping = mappings.find(m => m.sigma_field === sigmaField)
    return mapping?.target_field || null
  }

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

  const loadRule = async (ruleId: string) => {
    setIsLoading(true)
    try {
      const rule = await correlationRulesApi.get(ruleId)
      setFormData({
        name: rule.name,
        rule_a_id: rule.rule_a_id,
        rule_b_id: rule.rule_b_id,
        entity_field: rule.entity_field,
        time_window_minutes: rule.time_window_minutes,
        severity: rule.severity as any,
        is_enabled: rule.is_enabled,
      })
      // Load common fields with the current entity_field to ensure it's in the list
      await loadCommonFields(rule.entity_field)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load correlation rule')
    } finally {
      setIsLoading(false)
    }
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
          <p className="text-sm text-muted-foreground">
            {isEditing
              ? 'Modify the correlation rule configuration'
              : 'Define when two rules together indicate a higher-priority pattern'}
          </p>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Rule Configuration</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
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
                onValueChange={(value) => setFormData({ ...formData, severity: value as any })}
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

            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="is_enabled"
                checked={formData.is_enabled}
                onChange={(e) => setFormData({ ...formData, is_enabled: e.target.checked })}
                className="rounded"
              />
              <Label htmlFor="is_enabled" className="cursor-pointer">
                Enabled
              </Label>
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
              <Button type="submit" disabled={isSaving || isLoading || !formData.name || !formData.rule_a_id || !formData.rule_b_id}>
                {isSaving && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                {isEditing ? 'Update' : 'Create'} Rule
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
