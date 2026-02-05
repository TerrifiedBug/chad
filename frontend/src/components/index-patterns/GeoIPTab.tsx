import { useState, useEffect } from 'react'
import { IndexPattern, indexPatternsApi } from '@/lib/api'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Loader2, X } from 'lucide-react'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

interface GeoIPTabProps {
  pattern: IndexPattern
  onDirtyChange?: (isDirty: boolean) => void
  onPendingChange?: (changes: Partial<IndexPattern>) => void
}

// Common IP fields that are typically used for GeoIP enrichment
const COMMON_IP_FIELDS = [
  'source.ip',
  'destination.ip',
  'client.ip',
  'server.ip',
  'host.ip',
  'source.nat.ip',
  'destination.nat.ip',
  'network.forwarded_ip',
]

export function GeoIPTab({ pattern, onDirtyChange, onPendingChange }: GeoIPTabProps) {
  const [geoipFields, setGeoipFields] = useState<string[]>(pattern.geoip_fields || [])
  const [originalFields] = useState<string[]>(pattern.geoip_fields || [])
  const [availableFields, setAvailableFields] = useState<string[]>([])
  const [isLoading, setIsLoading] = useState(true)

  // Load available fields from the index
  useEffect(() => {
    const loadFields = async () => {
      setIsLoading(true)
      try {
        const fields = await indexPatternsApi.getFields(pattern.id)
        // Filter to likely IP fields (contain 'ip' in name or are in common list)
        const ipFields = fields.filter(f =>
          f.toLowerCase().includes('ip') ||
          f.toLowerCase().includes('address') ||
          COMMON_IP_FIELDS.includes(f)
        )
        setAvailableFields(ipFields.length > 0 ? ipFields : fields)
      } catch (err) {
        console.error('Failed to load fields:', err)
        setAvailableFields(COMMON_IP_FIELDS)
      } finally {
        setIsLoading(false)
      }
    }
    loadFields()
  }, [pattern.id])

  // Initialize from pattern
  useEffect(() => {
    setGeoipFields(pattern.geoip_fields || [])
  }, [pattern.geoip_fields])

  // Track dirty state and report pending changes
  useEffect(() => {
    const isDirty = JSON.stringify(geoipFields) !== JSON.stringify(originalFields)
    onDirtyChange?.(isDirty)
    if (isDirty) {
      onPendingChange?.({
        geoip_fields: geoipFields.length > 0 ? geoipFields : undefined,
      })
    }
  }, [geoipFields, originalFields, onDirtyChange, onPendingChange])

  const addField = (field: string) => {
    if (field && !geoipFields.includes(field)) {
      setGeoipFields([...geoipFields, field])
    }
  }

  const removeField = (field: string) => {
    setGeoipFields(geoipFields.filter(f => f !== field))
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-medium">GeoIP Enrichment</h3>
        <p className="text-sm text-muted-foreground">
          Select IP address fields to enrich with geographic location data (country, city, coordinates).
        </p>
      </div>

      <div className="space-y-4">
        <div className="space-y-2">
          <Label>IP Fields to Enrich</Label>
          <Select value="" onValueChange={addField}>
            <SelectTrigger>
              <SelectValue placeholder="Select an IP field to add..." />
            </SelectTrigger>
            <SelectContent>
              {availableFields
                .filter(f => !geoipFields.includes(f))
                .map((field) => (
                  <SelectItem key={field} value={field}>
                    {field}
                  </SelectItem>
                ))}
            </SelectContent>
          </Select>
        </div>

        {geoipFields.length > 0 ? (
          <div className="space-y-2">
            <Label className="text-sm text-muted-foreground">Selected Fields</Label>
            <div className="flex flex-wrap gap-2">
              {geoipFields.map((field) => (
                <Badge key={field} variant="secondary" className="flex items-center gap-1 pr-1">
                  {field}
                  <button
                    type="button"
                    onClick={() => removeField(field)}
                    className="ml-1 hover:bg-muted rounded-full p-0.5"
                  >
                    <X className="h-3 w-3" />
                  </button>
                </Badge>
              ))}
            </div>
          </div>
        ) : (
          <div className="text-sm text-muted-foreground py-4 text-center border border-dashed rounded-lg">
            No fields selected. Add IP fields above to enable GeoIP enrichment.
          </div>
        )}

        <div className="bg-muted/50 rounded-lg p-4 text-sm">
          <p className="font-medium mb-2">Enrichment adds the following fields:</p>
          <ul className="list-disc list-inside text-muted-foreground space-y-1">
            <li><code className="text-xs">{'{field}'}.geo.country_name</code> - Country name</li>
            <li><code className="text-xs">{'{field}'}.geo.city_name</code> - City name</li>
            <li><code className="text-xs">{'{field}'}.geo.location</code> - Geo point (lat/lon)</li>
            <li><code className="text-xs">{'{field}'}.geo.country_iso_code</code> - ISO country code</li>
          </ul>
        </div>
      </div>

    </div>
  )
}
