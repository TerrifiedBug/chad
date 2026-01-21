import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { rulesApi, indexPatternsApi, Rule, IndexPattern, RuleStatus } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Plus, Search } from 'lucide-react'

const severityColors: Record<string, string> = {
  critical: 'bg-red-500 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-500 text-black',
  low: 'bg-blue-500 text-white',
  informational: 'bg-gray-500 text-white',
}

const statusColors: Record<RuleStatus, string> = {
  enabled: 'bg-green-500 text-white',
  disabled: 'bg-gray-500 text-white',
  snoozed: 'bg-yellow-500 text-black',
}

export default function RulesPage() {
  const navigate = useNavigate()
  const [rules, setRules] = useState<Rule[]>([])
  const [indexPatterns, setIndexPatterns] = useState<Record<string, IndexPattern>>({})
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState<RuleStatus | 'all'>('all')

  useEffect(() => {
    loadData()
  }, [statusFilter])

  const loadData = async () => {
    setIsLoading(true)
    setError('')
    try {
      const [rulesData, patternsData] = await Promise.all([
        rulesApi.list(statusFilter === 'all' ? undefined : statusFilter),
        indexPatternsApi.list(),
      ])
      setRules(rulesData)
      // Create lookup map for index patterns
      const patternsMap: Record<string, IndexPattern> = {}
      patternsData.forEach((p) => {
        patternsMap[p.id] = p
      })
      setIndexPatterns(patternsMap)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load rules')
    } finally {
      setIsLoading(false)
    }
  }

  const filteredRules = rules.filter((rule) =>
    rule.title.toLowerCase().includes(search.toLowerCase())
  )

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    })
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Rules</h1>
        <Button onClick={() => navigate('/rules/new')}>
          <Plus className="h-4 w-4 mr-2" />
          Create Rule
        </Button>
      </div>

      <div className="flex gap-4">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search rules..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-10"
          />
        </div>
        <Select
          value={statusFilter}
          onValueChange={(value) => setStatusFilter(value as RuleStatus | 'all')}
        >
          <SelectTrigger className="w-40">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Status</SelectItem>
            <SelectItem value="enabled">Enabled</SelectItem>
            <SelectItem value="disabled">Disabled</SelectItem>
            <SelectItem value="snoozed">Snoozed</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {error && (
        <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md">
          {error}
        </div>
      )}

      {isLoading ? (
        <div className="text-center py-8 text-muted-foreground">Loading...</div>
      ) : filteredRules.length === 0 ? (
        <div className="text-center py-8 text-muted-foreground">
          {search ? 'No rules match your search' : 'No rules found. Create your first rule!'}
        </div>
      ) : (
        <div className="border rounded-lg">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Title</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Index Pattern</TableHead>
                <TableHead>Updated</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredRules.map((rule) => (
                <TableRow
                  key={rule.id}
                  className="cursor-pointer hover:bg-muted/50"
                  onClick={() => navigate(`/rules/${rule.id}`)}
                >
                  <TableCell className="font-medium">{rule.title}</TableCell>
                  <TableCell>
                    <span
                      className={`px-2 py-1 rounded text-xs font-medium ${
                        severityColors[rule.severity] || 'bg-gray-500 text-white'
                      }`}
                    >
                      {rule.severity}
                    </span>
                  </TableCell>
                  <TableCell>
                    <span
                      className={`px-2 py-1 rounded text-xs font-medium ${statusColors[rule.status]}`}
                    >
                      {rule.status}
                    </span>
                  </TableCell>
                  <TableCell>
                    {indexPatterns[rule.index_pattern_id]?.name || 'Unknown'}
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {formatDate(rule.updated_at)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  )
}
