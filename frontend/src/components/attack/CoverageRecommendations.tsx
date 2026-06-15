import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { recommendationsApi, CoverageRecommendation } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Lightbulb, CheckCircle2, AlertTriangle, ChevronRight } from 'lucide-react'

// Map a numeric priority score into a coarse band for the badge. The service
// scores roughly in the 0-20 range; these thresholds keep the labels stable.
function priorityBand(priority: number): { label: string; variant: 'destructive' | 'warning' | 'secondary' } {
  if (priority >= 12) return { label: 'High', variant: 'destructive' }
  if (priority >= 7) return { label: 'Medium', variant: 'warning' }
  return { label: 'Low', variant: 'secondary' }
}

interface CoverageRecommendationsProps {
  /** How many recommendations to request from the backend. */
  limit?: number
}

/**
 * F6 — "Deploy these next" panel.
 *
 * Lists the top coverage-gap recommendations from the ATT&CK matrix: uncovered
 * or weakly-covered techniques, each with concrete SigmaHQ rules to deploy and
 * a compatibility hint against the org's existing field mappings.
 */
export function CoverageRecommendations({ limit = 8 }: CoverageRecommendationsProps) {
  const navigate = useNavigate()

  const { data, isLoading, isError } = useQuery({
    queryKey: ['coverage-recommendations', limit],
    queryFn: () => recommendationsApi.coverage({ limit }),
  })

  return (
    <Card className="w-96 flex-shrink-0">
      <CardHeader className="pb-2">
        <CardTitle className="text-lg flex items-center gap-2">
          <Lightbulb className="h-5 w-5" />
          Deploy These Next
        </CardTitle>
        <p className="text-sm text-muted-foreground">
          Prioritised rule suggestions for your biggest coverage gaps
        </p>
      </CardHeader>
      <CardContent>
        {isLoading && (
          <div className="text-sm text-muted-foreground py-6 text-center">
            Analysing coverage gaps…
          </div>
        )}

        {isError && (
          <div className="text-sm text-destructive py-6 text-center">
            Failed to load recommendations
          </div>
        )}

        {!isLoading && !isError && data && data.recommendations.length === 0 && (
          <div className="text-sm text-muted-foreground py-6 text-center">
            No coverage gaps found — nice work.
          </div>
        )}

        {!isLoading && !isError && data && data.recommendations.length > 0 && (
          <ScrollArea className="h-[460px] pr-3">
            <div className="space-y-3">
              {data.recommendations.map((rec: CoverageRecommendation) => {
                const band = priorityBand(rec.priority)
                return (
                  <div
                    key={rec.technique_id}
                    className="rounded-md border p-3 space-y-2 bg-muted/30"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <div className="font-medium text-sm truncate" title={rec.technique_name}>
                          {rec.technique_name}
                        </div>
                        <div className="text-xs text-muted-foreground">
                          {rec.technique_id} · {rec.tactic}
                        </div>
                      </div>
                      <Badge variant={band.variant} className="shrink-0">
                        {band.label}
                      </Badge>
                    </div>

                    <p className="text-xs text-muted-foreground">{rec.reason}</p>

                    {rec.suggested_rules.length > 0 && (
                      <div className="space-y-1">
                        <div className="text-[11px] font-medium text-muted-foreground uppercase tracking-wide">
                          Suggested rules
                        </div>
                        {rec.suggested_rules.map((rule) => (
                          <div
                            key={rule.path}
                            className="flex items-center justify-between gap-2 text-xs rounded bg-background px-2 py-1.5 border"
                          >
                            <span className="truncate" title={rule.title}>
                              {rule.title}
                            </span>
                            {rule.compatible ? (
                              <span
                                className="flex items-center gap-1 text-status-healthy-foreground shrink-0"
                                title="All Sigma fields are already mapped in your environment"
                              >
                                <CheckCircle2 className="h-3.5 w-3.5" />
                                Ready
                              </span>
                            ) : (
                              <span
                                className="flex items-center gap-1 text-muted-foreground shrink-0"
                                title="May require new field mappings"
                              >
                                <AlertTriangle className="h-3.5 w-3.5" />
                                Needs mapping
                              </span>
                            )}
                          </div>
                        ))}
                      </div>
                    )}

                    <button
                      onClick={() => navigate('/sigmahq')}
                      className="text-xs text-primary hover:underline flex items-center gap-1 mt-1"
                    >
                      Browse in SigmaHQ <ChevronRight className="h-3 w-3" />
                    </button>
                  </div>
                )
              })}
            </div>
          </ScrollArea>
        )}
      </CardContent>
    </Card>
  )
}

export default CoverageRecommendations
