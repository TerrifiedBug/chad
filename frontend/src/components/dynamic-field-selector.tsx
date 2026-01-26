import { useEffect, useState } from 'react'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Label } from '@/components/ui/label'
import { Loader2 } from 'lucide-react'

interface DynamicFieldSelectorProps {
  ruleYaml: string
  value: string
  onChange: (value: string) => void
  label?: string
  placeholder?: string
  description?: string
  disabled?: boolean
}

export function DynamicFieldSelector({
  ruleYaml,
  value,
  onChange,
  label = "Field",
  placeholder = "Select a field...",
  description,
  disabled = false,
}: DynamicFieldSelectorProps) {
  const [fields, setFields] = useState<string[]>([])
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    const parseFields = async () => {
      if (!ruleYaml) return

      setLoading(true)
      try {
        const token = localStorage.getItem('chad-token')
        const headers: HeadersInit = {
          'Content-Type': 'application/json',
        }
        if (token) {
          headers['Authorization'] = `Bearer ${token}`
        }

        const response = await fetch('/api/rules/parse-fields', {
          method: 'POST',
          headers,
          body: JSON.stringify({ yaml_content: ruleYaml })
        })

        if (response.ok) {
          const data = await response.json()
          setFields(data.fields || [])
        }
      } catch (err) {
        console.error('Failed to parse fields:', err)
        setFields([])
      } finally {
        setLoading(false)
      }
    }

    parseFields()
  }, [ruleYaml])

  return (
    <div className="space-y-2">
      {label && <Label htmlFor="field-select">{label}</Label>}
      <Select value={value} onValueChange={onChange} disabled={loading || fields.length === 0 || disabled}>
        <SelectTrigger id="field-select">
          {loading ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <SelectValue placeholder={placeholder} />
          )}
        </SelectTrigger>
        <SelectContent className="z-50 bg-popover max-h-60">
          {fields.length === 0 ? (
            <div className="p-2 text-sm text-muted-foreground">
              No fields available - parse rule first
            </div>
          ) : (
            fields.map(field => (
              <SelectItem key={field} value={field}>
                {field}
              </SelectItem>
            ))
          )}
        </SelectContent>
      </Select>
      {description && (
        <p className="text-xs text-muted-foreground">{description}</p>
      )}
    </div>
  )
}
