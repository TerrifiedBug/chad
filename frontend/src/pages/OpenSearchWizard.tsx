import { useEffect, useState } from 'react'
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
  ssl_verification: 'SSL certificate verification...',
}

export default function OpenSearchWizard() {
  const navigate = useNavigate()
  const { setOpenSearchConfigured } = useAuth()
  const [isLoading, setIsLoading] = useState(false)
  const [isTesting, setIsTesting] = useState(false)
  const [isInitialLoading, setIsInitialLoading] = useState(true)
  const [testPassed, setTestPassed] = useState(false)
  const [error, setError] = useState('')
  const [validationSteps, setValidationSteps] = useState<ValidationStep[]>([])

  const [formData, setFormData] = useState<OpenSearchConfig>({
    host: '',
    port: 9200,
    username: '',
    password: '',
    use_ssl: true,
    verify_certs: true,
  })

  // Load existing config on mount
  useEffect(() => {
    const loadExistingConfig = async () => {
      try {
        const status = await settingsApi.getOpenSearchStatus()
        if (status.configured && status.config) {
          setFormData({
            host: status.config.host || '',
            port: status.config.port || 9200,
            username: status.config.username || '',
            password: '', // Never load existing password for security
            use_ssl: status.config.use_ssl ?? true,
            verify_certs: status.config.verify_certs ?? true,
          })
        }
      } catch (err) {
        // If not configured or error, just use defaults
        console.error('Failed to load existing config:', err)
      } finally {
        setIsInitialLoading(false)
      }
    }

    loadExistingConfig()
  }, [])

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

  const handleVerifyCertsChange = (checked: boolean) => {
    setFormData((prev) => ({ ...prev, verify_certs: checked }))
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
        verify_certs: formData.verify_certs,
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
        verify_certs: formData.verify_certs,
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
            {isInitialLoading ? (
              <div className="flex justify-center py-8">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
              </div>
            ) : (
              <>
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
                  disabled={isTesting}
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
                  disabled={isTesting}
                  className="[appearance:textfield] [&::-webkit-outer-spin-button]:m-0 [&::-webkit-outer-spin-button]:appearance-none [&::-webkit-inner-spin-button]:m-0 [&::-webkit-inner-spin-button]:appearance-none"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="username">Username (optional)</Label>
                <Input
                  id="username"
                  name="username"
                  value={formData.username}
                  onChange={handleChange}
                  disabled={isTesting}
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
                  disabled={isTesting}
                />
              </div>
              <div className="flex items-center justify-between">
                <Label htmlFor="use_ssl">Use SSL</Label>
                <Switch
                  id="use_ssl"
                  checked={formData.use_ssl}
                  onCheckedChange={handleSslChange}
                  disabled={isTesting}
                />
              </div>
              <div className="flex items-center justify-between">
                <div className="flex flex-col gap-1">
                  <Label htmlFor="verify_certs">Verify SSL Certificates</Label>
                  <p className="text-xs text-muted-foreground">
                    Disable only for development with self-signed certificates
                  </p>
                </div>
                <Switch
                  id="verify_certs"
                  checked={formData.verify_certs ?? true}
                  onCheckedChange={handleVerifyCertsChange}
                  disabled={isTesting || !formData.use_ssl}
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
                    <div className="flex-1">
                      <span className={step.success ? 'text-muted-foreground' : 'text-destructive'}>
                        {stepLabels[step.name] || step.name}
                      </span>
                      {step.error && step.name === 'ssl_verification' && (
                        <span className="ml-2 text-xs text-muted-foreground">
                          ({step.error})
                        </span>
                      )}
                    </div>
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
                disabled={isLoading || !testPassed || isTesting}
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
            </>
            )}
          </CardContent>
        </Card>
    </div>
  )
}
