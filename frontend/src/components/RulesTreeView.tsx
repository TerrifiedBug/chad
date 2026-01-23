import { useState } from 'react'
import { ChevronRight, ChevronDown, FileText } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import type { Rule, IndexPattern } from '@/lib/api'

interface RulesTreeViewProps {
  rules: Rule[]
  indexPatterns: Record<string, IndexPattern>
  onRuleClick: (rule: Rule) => void
  selectedRules?: Set<string>
  onRuleSelect?: (ruleId: string, index: number, shiftKey: boolean) => void
}

export function RulesTreeView({
  rules,
  indexPatterns,
  onRuleClick,
  selectedRules,
  onRuleSelect,
}: RulesTreeViewProps) {
  const [expandedPatterns, setExpandedPatterns] = useState<Set<string>>(new Set())

  // Group rules by index pattern
  const rulesByPattern = rules.reduce(
    (acc, rule) => {
      const patternId = rule.index_pattern_id
      if (!acc[patternId]) {
        acc[patternId] = []
      }
      acc[patternId].push(rule)
      return acc
    },
    {} as Record<string, Rule[]>
  )

  const togglePattern = (patternId: string) => {
    setExpandedPatterns((prev) => {
      const newSet = new Set(prev)
      if (newSet.has(patternId)) {
        newSet.delete(patternId)
      } else {
        newSet.add(patternId)
      }
      return newSet
    })
  }

  const getPatternName = (patternId: string) => {
    return indexPatterns[patternId]?.name || 'Unknown'
  }

  const getSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'bg-red-500'
      case 'high':
        return 'bg-orange-500'
      case 'medium':
        return 'bg-yellow-500'
      case 'low':
        return 'bg-blue-500'
      default:
        return 'bg-gray-500'
    }
  }

  // Calculate global index for shift+click - we need to track this across all patterns
  let globalIndex = 0

  return (
    <div className="space-y-1 border rounded-lg p-2">
      {Object.entries(rulesByPattern).map(([patternId, patternRules]) => {
        // Store the starting index for this pattern's rules
        const patternStartIndex = globalIndex

        return (
          <div key={patternId}>
            <button
              className="flex items-center gap-2 w-full p-2 hover:bg-muted rounded-md text-left"
              onClick={() => togglePattern(patternId)}
            >
              {expandedPatterns.has(patternId) ? (
                <ChevronDown className="h-4 w-4" />
              ) : (
                <ChevronRight className="h-4 w-4" />
              )}
              <span className="font-medium">{getPatternName(patternId)}</span>
              <Badge variant="secondary" className="ml-auto">
                {patternRules.length}
              </Badge>
            </button>

            {expandedPatterns.has(patternId) && (
              <div className="ml-6 space-y-1">
                {patternRules.map((rule, ruleIndex) => {
                  const currentIndex = patternStartIndex + ruleIndex
                  const isSelected = selectedRules?.has(rule.id)

                  return (
                    <button
                      key={rule.id}
                      className={cn(
                        'flex items-center gap-2 w-full p-2 hover:bg-muted rounded-md text-left',
                        isSelected && 'bg-muted'
                      )}
                      onClick={(e) => {
                        if (onRuleSelect) {
                          onRuleSelect(rule.id, currentIndex, e.shiftKey)
                        } else {
                          onRuleClick(rule)
                        }
                      }}
                      onDoubleClick={() => onRuleClick(rule)}
                    >
                      <FileText className="h-4 w-4 text-muted-foreground" />
                      <span
                        className={cn(rule.status === 'disabled' && 'text-muted-foreground line-through')}
                      >
                        {rule.title}
                      </span>
                      <div className="flex items-center gap-1 ml-auto">
                        <div
                          className={cn('w-2 h-2 rounded-full', getSeverityColor(rule.severity))}
                        />
                        {rule.status === 'disabled' && (
                          <Badge variant="secondary" className="text-xs bg-gray-400 text-white">
                            disabled
                          </Badge>
                        )}
                        {rule.status === 'snoozed' && (
                          <Badge variant="secondary" className="text-xs bg-yellow-500 text-white">
                            snoozed
                          </Badge>
                        )}
                        {rule.deployed_at && (
                          <Badge variant="outline" className="text-xs">
                            deployed
                          </Badge>
                        )}
                      </div>
                    </button>
                  )
                })}
              </div>
            )}
            {/* Update global index after processing this pattern */}
            {(() => {
              globalIndex += patternRules.length
              return null
            })()}
          </div>
        )
      })}

      {Object.keys(rulesByPattern).length === 0 && (
        <div className="text-center text-muted-foreground py-8">No rules found</div>
      )}
    </div>
  )
}
