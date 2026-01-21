import { useState } from 'react'
import { useAuth } from '@/hooks/use-auth'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Switch } from '@/components/ui/switch'

export default function SetupPage() {
  const { setup } = useAuth()
  const [error, setError] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [formData, setFormData] = useState({
    admin_email: '',
    admin_password: '',
    confirm_password: '',
    opensearch_host: '',
    opensearch_port: 9200,
    opensearch_username: '',
    opensearch_password: '',
    opensearch_use_ssl: true,
  })

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')

    if (formData.admin_password !== formData.confirm_password) {
      setError('Passwords do not match')
      return
    }

    if (formData.admin_password.length < 8) {
      setError('Password must be at least 8 characters')
      return
    }

    setIsLoading(true)
    try {
      await setup({
        admin_email: formData.admin_email,
        admin_password: formData.admin_password,
        opensearch_host: formData.opensearch_host,
        opensearch_port: formData.opensearch_port,
        opensearch_username: formData.opensearch_username || undefined,
        opensearch_password: formData.opensearch_password || undefined,
        opensearch_use_ssl: formData.opensearch_use_ssl,
      })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Setup failed')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <Card className="w-full max-w-lg">
        <CardHeader className="text-center">
          <CardTitle className="text-3xl">Welcome to CHAD</CardTitle>
          <CardDescription>
            Cyber Hunting And Detection - Initial Setup
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Admin Account Section */}
            <div className="space-y-4">
              <h3 className="text-lg font-medium">Admin Account</h3>
              <div className="space-y-2">
                <Label htmlFor="admin_email">Email</Label>
                <Input
                  id="admin_email"
                  type="email"
                  placeholder="admin@example.com"
                  value={formData.admin_email}
                  onChange={(e) => setFormData({ ...formData, admin_email: e.target.value })}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="admin_password">Password</Label>
                <Input
                  id="admin_password"
                  type="password"
                  value={formData.admin_password}
                  onChange={(e) => setFormData({ ...formData, admin_password: e.target.value })}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="confirm_password">Confirm Password</Label>
                <Input
                  id="confirm_password"
                  type="password"
                  value={formData.confirm_password}
                  onChange={(e) => setFormData({ ...formData, confirm_password: e.target.value })}
                  required
                />
              </div>
            </div>

            {/* OpenSearch Section */}
            <div className="space-y-4">
              <h3 className="text-lg font-medium">OpenSearch Connection</h3>
              <div className="space-y-2">
                <Label htmlFor="opensearch_host">Host</Label>
                <Input
                  id="opensearch_host"
                  type="text"
                  placeholder="opensearch.example.com"
                  value={formData.opensearch_host}
                  onChange={(e) => setFormData({ ...formData, opensearch_host: e.target.value })}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="opensearch_port">Port</Label>
                <Input
                  id="opensearch_port"
                  type="number"
                  value={formData.opensearch_port}
                  onChange={(e) => setFormData({ ...formData, opensearch_port: parseInt(e.target.value) })}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="opensearch_username">Username (optional)</Label>
                <Input
                  id="opensearch_username"
                  type="text"
                  value={formData.opensearch_username}
                  onChange={(e) => setFormData({ ...formData, opensearch_username: e.target.value })}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="opensearch_password">Password (optional)</Label>
                <Input
                  id="opensearch_password"
                  type="password"
                  value={formData.opensearch_password}
                  onChange={(e) => setFormData({ ...formData, opensearch_password: e.target.value })}
                />
              </div>
              <div className="flex items-center space-x-2">
                <Switch
                  id="opensearch_use_ssl"
                  checked={formData.opensearch_use_ssl}
                  onCheckedChange={(checked) => setFormData({ ...formData, opensearch_use_ssl: checked })}
                />
                <Label htmlFor="opensearch_use_ssl">Use SSL/TLS</Label>
              </div>
            </div>

            {error && (
              <div className="text-destructive text-sm">{error}</div>
            )}

            <Button type="submit" className="w-full" disabled={isLoading}>
              {isLoading ? 'Setting up...' : 'Complete Setup'}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
