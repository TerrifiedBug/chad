import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import {
  rulesApi,
  indexPatternsApi,
  IndexPattern,
  ValidationError,
  LogMatchResult,
} from '@/lib/api'
import { YamlEditor } from '@/components/YamlEditor'
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
import { Switch } from '@/components/ui/switch'
import yaml from 'js-yaml'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { ArrowLeft, Check, X, Play, AlertCircle, Rocket, RotateCcw } from 'lucide-react'

const DEFAULT_RULE = `title: My Detection Rule
status: experimental
description: |
  Describe what this rule detects
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    CommandLine|contains: 'suspicious'
  condition: selection
level: medium
`

export default function RuleEditorPage() {
  const navigate = useNavigate()
  const { id } = useParams<{ id: string }>()
  const isNew = !id || id === 'new'

  // Form state
  const [title, setTitle] = useState('')
  const [yamlContent, setYamlContent] = useState(DEFAULT_RULE)
  const [severity, setSeverity] = useState('medium')
  const [indexPatternId, setIndexPatternId] = useState('')
  const [description, setDescription] = useState('')
  const [status, setStatus] = useState<'enabled' | 'disabled'>('disabled')

  // UI state
  const [indexPatterns, setIndexPatterns] = useState<IndexPattern[]>([])
  const [isLoading, setIsLoading] = useState(!isNew)
  const [isSaving, setIsSaving] = useState(false)
  const [error, setError] = useState('')

  // Validation state
  const [validationErrors, setValidationErrors] = useState<ValidationError[]>([])
  const [isValidating, setIsValidating] = useState(false)
  const [isValid, setIsValid] = useState<boolean | null>(null)
  const [generatedQuery, setGeneratedQuery] = useState<Record<string, unknown> | null>(null)

  // Test state
  const [sampleLog, setSampleLog] = useState('{\n  "CommandLine": "cmd.exe /c whoami"\n}')
  const [isTesting, setIsTesting] = useState(false)
  const [testResults, setTestResults] = useState<LogMatchResult[] | null>(null)

  // Deployment state
  const [deployedAt, setDeployedAt] = useState<string | null>(null)
  const [deployedVersion, setDeployedVersion] = useState<number | null>(null)
  const [currentVersion, setCurrentVersion] = useState<number>(1)
  const [isDeploying, setIsDeploying] = useState(false)
  const [deployError, setDeployError] = useState('')
  const [saveSuccess, setSaveSuccess] = useState(false)

  useEffect(() => {
    loadIndexPatterns()
    if (!isNew) {
      loadRule()
    }
  }, [id])

  // Debounced validation
  useEffect(() => {
    const timer = setTimeout(() => {
      if (yamlContent.trim()) {
        validateRule()
      }
    }, 500)
    return () => clearTimeout(timer)
  }, [yamlContent, indexPatternId])

  const loadIndexPatterns = async () => {
    try {
      const patterns = await indexPatternsApi.list()
      setIndexPatterns(patterns)
      if (patterns.length > 0 && !indexPatternId) {
        setIndexPatternId(patterns[0].id)
      }
    } catch (err) {
      console.error('Failed to load index patterns:', err)
    }
  }

  const loadRule = async () => {
    if (!id) return
    setIsLoading(true)
    try {
      const rule = await rulesApi.get(id)
      setTitle(rule.title)
      setYamlContent(rule.yaml_content)
      setSeverity(rule.severity)
      setIndexPatternId(rule.index_pattern_id)
      setDescription(rule.description || '')
      setDeployedAt(rule.deployed_at)
      setDeployedVersion(rule.deployed_version)
      setStatus(rule.status as 'enabled' | 'disabled')
      // Get current version from versions array (sorted desc by version_number)
      if (rule.versions && rule.versions.length > 0) {
        setCurrentVersion(rule.versions[0].version_number)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load rule')
    } finally {
      setIsLoading(false)
    }
  }

  const validateRule = async () => {
    setIsValidating(true)
    try {
      const result = await rulesApi.validate(
        yamlContent,
        indexPatternId || undefined
      )
      setValidationErrors(result.errors)
      setIsValid(result.valid)
      setGeneratedQuery(result.opensearch_query || null)
    } catch (err) {
      setValidationErrors([
        { type: 'error', message: err instanceof Error ? err.message : 'Validation failed' },
      ])
      setIsValid(false)
    } finally {
      setIsValidating(false)
    }
  }

  const handleTest = async () => {
    setIsTesting(true)
    setTestResults(null)
    try {
      // Parse sample log JSON
      let logs: Record<string, unknown>[]
      try {
        const parsed = JSON.parse(sampleLog)
        logs = Array.isArray(parsed) ? parsed : [parsed]
      } catch {
        setTestResults([])
        setError('Invalid JSON in sample log')
        setIsTesting(false)
        return
      }

      const result = await rulesApi.test(yamlContent, logs)
      if (result.errors.length > 0) {
        setValidationErrors(result.errors)
        setIsValid(false)
      } else {
        setTestResults(result.matches)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Test failed')
    } finally {
      setIsTesting(false)
    }
  }

  // Extract title and level from YAML when it changes
  const syncFromYaml = (yamlStr: string) => {
    try {
      const parsed = yaml.load(yamlStr) as Record<string, unknown>
      if (parsed?.title && typeof parsed.title === 'string') {
        setTitle(parsed.title)
      }
      if (parsed?.level && typeof parsed.level === 'string') {
        const level = parsed.level.toLowerCase()
        if (['critical', 'high', 'medium', 'low', 'informational'].includes(level)) {
          setSeverity(level)
        }
      }
    } catch {
      // Invalid YAML, ignore
    }
  }

  const handleYamlChange = (newYaml: string) => {
    setYamlContent(newYaml)
    syncFromYaml(newYaml)
  }

  const handleTitleChange = (newTitle: string) => {
    setTitle(newTitle)
    // Update YAML
    const updatedYaml = yamlContent.replace(
      /^title:\s*.+$/m,
      `title: ${newTitle}`
    )
    if (updatedYaml !== yamlContent) {
      setYamlContent(updatedYaml)
    }
  }

  const handleSeverityChange = (newSeverity: string) => {
    setSeverity(newSeverity)
    // Update YAML level field
    const updatedYaml = yamlContent.replace(
      /^level:\s*.+$/m,
      `level: ${newSeverity}`
    )
    if (updatedYaml !== yamlContent) {
      setYamlContent(updatedYaml)
    }
  }

  const handleSave = async () => {
    if (!isValid) {
      setError('Please fix validation errors before saving')
      return
    }

    if (!title.trim()) {
      setError('Title is required')
      return
    }

    if (!indexPatternId) {
      setError('Index pattern is required')
      return
    }

    setIsSaving(true)
    setError('')
    setSaveSuccess(false)

    try {
      if (isNew) {
        const newRule = await rulesApi.create({
          title,
          description: description || undefined,
          yaml_content: yamlContent,
          severity,
          status,
          index_pattern_id: indexPatternId,
        })
        // Navigate to the edit page for the new rule
        navigate(`/rules/${newRule.id}`, { replace: true })
      } else {
        await rulesApi.update(id!, {
          title,
          description: description || undefined,
          yaml_content: yamlContent,
          severity,
          status,
          index_pattern_id: indexPatternId,
        })
        // Reload rule to get updated version
        await loadRule()
        setSaveSuccess(true)
        // Clear success message after 3 seconds
        setTimeout(() => setSaveSuccess(false), 3000)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Save failed')
    } finally {
      setIsSaving(false)
    }
  }

  const handleDeploy = async () => {
    if (!id) return
    setIsDeploying(true)
    setDeployError('')
    try {
      const result = await rulesApi.deploy(id)
      setDeployedAt(result.deployed_at)
      setDeployedVersion(result.deployed_version)
      // deployed_version should now match currentVersion
    } catch (err) {
      setDeployError(err instanceof Error ? err.message : 'Deploy failed')
    } finally {
      setIsDeploying(false)
    }
  }

  const handleUndeploy = async () => {
    if (!id) return
    setIsDeploying(true)
    setDeployError('')
    try {
      await rulesApi.undeploy(id)
      setDeployedAt(null)
      setDeployedVersion(null)
    } catch (err) {
      setDeployError(err instanceof Error ? err.message : 'Undeploy failed')
    } finally {
      setIsDeploying(false)
    }
  }

  const editorErrors = validationErrors
    .filter((e) => e.line)
    .map((e) => ({ line: e.line!, message: e.message }))

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-muted-foreground">Loading...</div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={() => navigate('/rules')}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <h1 className="text-2xl font-bold">
              {isNew ? 'Create Rule' : 'Edit Rule'}
              {!isNew && <span className="text-sm font-normal text-muted-foreground ml-2">v{currentVersion}</span>}
            </h1>
            {!isNew && deployedAt && (
              <p className={`text-xs ${deployedVersion === currentVersion ? 'text-green-600' : 'text-yellow-600'}`}>
                {deployedVersion === currentVersion
                  ? `Deployed v${deployedVersion}`
                  : `Deployed v${deployedVersion} (current is v${currentVersion} - redeploy needed)`
                }
              </p>
            )}
            {!isNew && !deployedAt && (
              <p className="text-xs text-muted-foreground">Not deployed</p>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2">
          {!isNew && (
            <div className="flex items-center gap-2 mr-4">
              <Switch
                checked={status === 'enabled'}
                onCheckedChange={(checked) => setStatus(checked ? 'enabled' : 'disabled')}
              />
              <Label className="text-sm">
                {status === 'enabled' ? 'Enabled' : 'Disabled'}
              </Label>
            </div>
          )}
          {saveSuccess && (
            <span className="text-sm text-green-600 flex items-center gap-1">
              <Check className="h-4 w-4" />
              Saved
            </span>
          )}
          {!isNew && (
            deployedAt ? (
              <>
                {deployedVersion !== currentVersion && (
                  <Button
                    variant="outline"
                    onClick={handleDeploy}
                    disabled={isDeploying || !isValid}
                  >
                    <Rocket className="h-4 w-4 mr-2" />
                    {isDeploying ? 'Deploying...' : 'Redeploy'}
                  </Button>
                )}
                <Button
                  variant="ghost"
                  onClick={handleUndeploy}
                  disabled={isDeploying}
                >
                  <RotateCcw className="h-4 w-4 mr-2" />
                  {isDeploying ? 'Undeploying...' : 'Undeploy'}
                </Button>
              </>
            ) : (
              <Button
                variant="outline"
                onClick={handleDeploy}
                disabled={isDeploying || !isValid}
              >
                <Rocket className="h-4 w-4 mr-2" />
                {isDeploying ? 'Deploying...' : 'Deploy'}
              </Button>
            )
          )}
          <Button onClick={handleSave} disabled={isSaving || !isValid}>
            {isSaving ? 'Saving...' : 'Save'}
          </Button>
        </div>
      </div>

      {error && (
        <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md flex items-center gap-2">
          <AlertCircle className="h-4 w-4" />
          {error}
        </div>
      )}

      {deployError && (
        <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md flex items-center gap-2">
          <AlertCircle className="h-4 w-4" />
          Deployment error: {deployError}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Editor - 2 columns */}
        <div className="lg:col-span-2 space-y-4">
          <div className="space-y-2">
            <Label htmlFor="title">Title</Label>
            <Input
              id="title"
              value={title}
              onChange={(e) => handleTitleChange(e.target.value)}
              placeholder="Detection rule title"
            />
          </div>

          <div className="border rounded-lg overflow-hidden">
            <YamlEditor
              value={yamlContent}
              onChange={handleYamlChange}
              height="400px"
              errors={editorErrors}
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>Index Pattern</Label>
              <Select value={indexPatternId} onValueChange={setIndexPatternId}>
                <SelectTrigger>
                  <SelectValue placeholder="Select index pattern" />
                </SelectTrigger>
                <SelectContent className="z-50">
                  {indexPatterns.map((pattern) => (
                    <SelectItem key={pattern.id} value={pattern.id}>
                      {pattern.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Severity</Label>
              <Select value={severity} onValueChange={handleSeverityChange}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="z-50">
                  <SelectItem value="informational">Informational</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </div>

        {/* Side Panel - 1 column */}
        <div className="space-y-4">
          {/* Validation Card */}
          <Card>
            <CardHeader className="py-3">
              <CardTitle className="text-sm font-medium">Validation</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {isValidating ? (
                <div className="text-sm text-muted-foreground">Validating...</div>
              ) : isValid === null ? (
                <div className="text-sm text-muted-foreground">
                  Enter a rule to validate
                </div>
              ) : isValid ? (
                <div className="flex items-center gap-2 text-sm text-green-600">
                  <Check className="h-4 w-4" />
                  Rule is valid
                </div>
              ) : (
                <div className="space-y-2">
                  {validationErrors.map((error, idx) => (
                    <div
                      key={idx}
                      className="flex items-start gap-2 text-sm text-destructive"
                    >
                      <X className="h-4 w-4 mt-0.5 shrink-0" />
                      <span>
                        {error.line && `Line ${error.line}: `}
                        {error.message}
                      </span>
                    </div>
                  ))}
                </div>
              )}

              {generatedQuery && (
                <details className="mt-4">
                  <summary className="text-sm text-muted-foreground cursor-pointer">
                    View OpenSearch Query
                  </summary>
                  <pre className="mt-2 p-2 bg-muted rounded text-xs overflow-auto max-h-40">
                    {JSON.stringify(generatedQuery, null, 2)}
                  </pre>
                </details>
              )}
            </CardContent>
          </Card>

          {/* Test Card */}
          <Card>
            <CardHeader className="py-3">
              <CardTitle className="text-sm font-medium">Test Rule</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="space-y-2">
                <Label className="text-xs">Sample Log (JSON)</Label>
                <textarea
                  value={sampleLog}
                  onChange={(e) => setSampleLog(e.target.value)}
                  className="w-full h-32 p-2 text-xs font-mono border rounded-md bg-background resize-none"
                  placeholder='{"field": "value"}'
                />
              </div>
              <Button
                size="sm"
                variant="secondary"
                onClick={handleTest}
                disabled={isTesting || !isValid}
                className="w-full"
              >
                <Play className="h-3 w-3 mr-2" />
                {isTesting ? 'Testing...' : 'Test'}
              </Button>

              {testResults && (
                <div className="space-y-1">
                  {testResults.map((result, idx) => (
                    <div
                      key={idx}
                      className={`flex items-center gap-2 text-sm ${
                        result.matched ? 'text-green-600' : 'text-muted-foreground'
                      }`}
                    >
                      {result.matched ? (
                        <Check className="h-4 w-4" />
                      ) : (
                        <X className="h-4 w-4" />
                      )}
                      Log {result.log_index + 1}: {result.matched ? 'Matched' : 'No match'}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}
