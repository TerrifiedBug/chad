import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '@/hooks/use-auth'
import { settingsApi, OpenSearchConfig, ValidationStep } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Switch } from '@/components/ui/switch'

const stepLabels: Record<string, string> = {
  connectivity: 'Connecting to host...',
  authentication: 'Authenticating...',
  create_index: 'Creating test index...',
  index_query: 'Indexing test query...',
  percolate: 'Running percolate query...',
  cleanup: 'Cleaning up test artifacts...',
}

export default function OpenSearchWizard() {
  const navigate = useNavigate()
  const { setOpenSearchConfigured } = useAuth()
  const [isLoading, setIsLoading] = useState(false)
  const [isTesting, setIsTesting] = useState(false)
  const [testPassed, setTestPassed] = useState(false)
  const [error, setError] = useState('')
  const [validationSteps, setValidationSteps] = useState<ValidationStep[]>([])

  const [formData, setFormData] = useState<OpenSearchConfig>({
    host: '',
    port: 9200,
    username: '',
    password: '',
    use_ssl: true,
  })

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value, type } = e.target
    setFormData((prev) => ({
      ...prev,
      [name]: type === 'number' ? parseInt(value) || 0 : value,
    }))
    // Reset test state when config changes
    setTestPassed(false)
    setValidationSteps([])
  }

  const handleSslChange = (checked: boolean) => {
    setFormData((prev) => ({ ...prev, use_ssl: checked }))
    setTestPassed(false)
    setValidationSteps([])
  }

  const handleTest = async () => {
    setError('')
    setIsTesting(true)
    setValidationSteps([])
    setTestPassed(false)

    try {
      const config: OpenSearchConfig = {
        host: formData.host,
        port: formData.port,
        username: formData.username || undefined,
        password: formData.password || undefined,
        use_ssl: formData.use_ssl,
      }

      const result = await settingsApi.testOpenSearch(config)
      setValidationSteps(result.steps)
      setTestPassed(result.success)

      if (!result.success) {
        const failedStep = result.steps.find(s => !s.success)
        setError(failedStep?.error || 'Validation failed')
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Test failed')
    } finally {
      setIsTesting(false)
    }
  }

  const handleSave = async () => {
    if (!testPassed) return

    setIsLoading(true)
    setError('')

    try {
      const config: OpenSearchConfig = {
        host: formData.host,
        port: formData.port,
        username: formData.username || undefined,
        password: formData.password || undefined,
        use_ssl: formData.use_ssl,
      }

      await settingsApi.saveOpenSearch(config)
      setOpenSearchConfigured(true)
      navigate('/')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Save failed')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="flex items-center justify-center py-12 px-4">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <CardTitle className="text-2xl">Configure OpenSearch</CardTitle>
            <CardDescription>
              Connect CHAD to your OpenSearch cluster
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {error && (
              <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md">
                {error}
              </div>
            )}

            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="host">Host</Label>
                <Input
                  id="host"
                  name="host"
                  value={formData.host}
                  onChange={handleChange}
                  placeholder="opensearch.example.com"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="port">Port</Label>
                <Input
                  id="port"
                  name="port"
                  type="number"
                  value={formData.port}
                  onChange={handleChange}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="username">Username (optional)</Label>
                <Input
                  id="username"
                  name="username"
                  value={formData.username}
                  onChange={handleChange}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password">Password (optional)</Label>
                <Input
                  id="password"
                  name="password"
                  type="password"
                  value={formData.password}
                  onChange={handleChange}
                />
              </div>
              <div className="flex items-center justify-between">
                <Label htmlFor="use_ssl">Use SSL</Label>
                <Switch
                  id="use_ssl"
                  checked={formData.use_ssl}
                  onCheckedChange={handleSslChange}
                />
              </div>
            </div>

            {/* Validation Steps Display */}
            {validationSteps.length > 0 && (
              <div className="space-y-2 p-4 border rounded-md bg-muted/50">
                {validationSteps.map((step, index) => (
                  <div key={index} className="flex items-center gap-2 text-sm">
                    {step.success ? (
                      <span className="text-green-600">✓</span>
                    ) : (
                      <span className="text-red-600">✗</span>
                    )}
                    <span className={step.success ? 'text-muted-foreground' : 'text-destructive'}>
                      {stepLabels[step.name] || step.name}
                    </span>
                  </div>
                ))}
              </div>
            )}

            <div className="flex gap-3">
              <Button
                type="button"
                variant="secondary"
                onClick={handleTest}
                disabled={isTesting || !formData.host}
                className="flex-1"
              >
                {isTesting ? 'Testing...' : 'Test Connection'}
              </Button>
              <Button
                type="button"
                onClick={handleSave}
                disabled={isLoading || !testPassed}
                className="flex-1"
              >
                {isLoading ? 'Saving...' : 'Save & Continue'}
              </Button>
            </div>

            {!testPassed && validationSteps.length === 0 && (
              <p className="text-sm text-muted-foreground text-center">
                Click "Test Connection" to validate your OpenSearch configuration
              </p>
            )}
          </CardContent>
        </Card>
    </div>
  )
}
