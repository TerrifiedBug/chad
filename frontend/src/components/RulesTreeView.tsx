import { useState, useMemo } from 'react'
import { ChevronRight, ChevronDown, FileText, FileCode } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'
import { formatDistanceToNow } from 'date-fns'
import type { Rule, IndexPattern } from '@/lib/api'

interface RulesTreeViewProps {
  rules: Rule[]
  indexPatterns: Record<string, IndexPattern>
  onRuleClick: (rule: Rule) => void
  selectedRules?: Set<string>
  onRuleSelect?: (ruleId: string, index: number, shiftKey: boolean) => void
}

const severityConfig: Record<string, { label: string; className: string }> = {
  critical: { label: 'Critical', className: 'bg-red-500 text-white' },
  high: { label: 'High', className: 'bg-orange-500 text-white' },
  medium: { label: 'Medium', className: 'bg-yellow-500 text-black' },
  low: { label: 'Low', className: 'bg-blue-500 text-white' },
  informational: { label: 'Info', className: 'bg-gray-500 text-white' },
}

function getSnoozeDisplay(rule: Rule): string | null {
  if (rule.status !== 'snoozed') return null
  if (rule.snooze_indefinite) return '(indefinite)'
  if (rule.snooze_until) {
    return formatDistanceToNow(new Date(rule.snooze_until), { addSuffix: false })
  }
  return null
}

function getLastEditedText(rule: Rule): string {
  const timeAgo = formatDistanceToNow(new Date(rule.updated_at), { addSuffix: true })
  if (rule.last_edited_by) {
    return `Last edited by ${rule.last_edited_by} ${timeAgo}`
  }
  return `Last edited ${timeAgo}`
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

  const getSeverityConfig = (severity: string) => {
    const key = severity?.toLowerCase() || 'informational'
    return severityConfig[key] || severityConfig.informational
  }

  // Precompute pattern start indices for shift+click selection
  const patternStartIndices = useMemo(() => {
    const indices: Record<string, number> = {}
    let currentIndex = 0
    Object.entries(rulesByPattern).forEach(([patternId, patternRules]) => {
      indices[patternId] = currentIndex
      currentIndex += patternRules.length
    })
    return indices
  }, [rulesByPattern])

  return (
    <TooltipProvider>
      <div className="space-y-1 border rounded-lg p-2">
        {Object.entries(rulesByPattern).map(([patternId, patternRules]) => {
          const patternStartIndex = patternStartIndices[patternId]

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
                    const severityConf = getSeverityConfig(rule.severity)
                    const snoozeDisplay = getSnoozeDisplay(rule)
                    const isSigmaHQ = rule.source === 'sigmahq'

                    return (
                      <Tooltip key={rule.id}>
                        <TooltipTrigger asChild>
                          <button
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
                            {/* Source icon */}
                            {isSigmaHQ ? (
                              <FileCode className="h-4 w-4 text-blue-500 flex-shrink-0" />
                            ) : (
                              <FileText className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                            )}

                            {/* Title with strikethrough if indefinitely snoozed */}
                            <span
                              className={cn(
                                'truncate',
                                rule.snooze_indefinite && 'line-through text-muted-foreground'
                              )}
                            >
                              {rule.title}
                            </span>

                            {/* Badges container */}
                            <div className="flex items-center gap-1 ml-auto flex-shrink-0">
                              {/* Severity badge with label */}
                              <Badge className={cn('text-xs', severityConf.className)}>
                                {severityConf.label}
                              </Badge>

                              {/* Deployed badge */}
                              {rule.deployed_at && (
                                <Badge variant="outline" className="text-xs">
                                  Deployed
                                </Badge>
                              )}

                              {/* Snoozed badge with duration */}
                              {rule.status === 'snoozed' && (
                                <Badge className="text-xs bg-yellow-500 text-black">
                                  Snoozed {snoozeDisplay}
                                </Badge>
                              )}
                            </div>
                          </button>
                        </TooltipTrigger>
                        <TooltipContent side="top" align="start">
                          <p>{getLastEditedText(rule)}</p>
                        </TooltipContent>
                      </Tooltip>
                    )
                  })}
                </div>
              )}
            </div>
          )
        })}

        {Object.keys(rulesByPattern).length === 0 && (
          <div className="text-center text-muted-foreground py-8">No rules found</div>
        )}
      </div>
    </TooltipProvider>
  )
}
