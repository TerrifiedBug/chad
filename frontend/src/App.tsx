import { Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { ThemeProvider } from '@/hooks/use-theme'
import { AuthProvider, useAuth } from '@/hooks/use-auth'
import { ToastProvider } from '@/components/ui/toast-provider'
import { Header } from '@/components/Header'
import { ProtectedRoute } from '@/components/protected-route'
import SetupPage from '@/pages/Setup'
import LoginPage from '@/pages/Login'
import OpenSearchWizard from '@/pages/OpenSearchWizard'
import Dashboard from '@/pages/Dashboard'
import RulesPage from '@/pages/Rules'
import RuleEditorPage from '@/pages/RuleEditor'
import IndexPatternsPage from '@/pages/IndexPatterns'
import AlertsPage from '@/pages/Alerts'
import AlertDetailPage from '@/pages/AlertDetail'
import SettingsPage from '@/pages/Settings'
import UsersPage from '@/pages/Users'
import ChangePasswordPage from '@/pages/ChangePassword'
import ApiKeysPage from '@/pages/ApiKeys'
import SigmaHQPage from '@/pages/SigmaHQ'
import AuditLogPage from '@/pages/AuditLog'
import HealthPage from '@/pages/Health'
import FieldMappingsPage from '@/pages/FieldMappings'
import AttackMatrixPage from '@/pages/AttackMatrix'
import AccountPage from '@/pages/Account'
import CorrelationRulesPage from '@/pages/CorrelationRules'
import CorrelationRuleEditorPage from '@/pages/CorrelationRuleEditor'
import LiveAlertFeedPage from '@/pages/LiveAlertFeed'

function AuthRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading, user } = useAuth()
  const location = useLocation()

  if (isLoading) {
    return <div className="flex h-screen items-center justify-center">Loading...</div>
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }

  // Force password change for local users who must change their password
  if (user?.must_change_password && location.pathname !== '/change-password') {
    return <Navigate to="/change-password" replace />
  }

  return <>{children}</>
}

function AppRoutes() {
  const { setupCompleted, isLoading, isAuthenticated, isOpenSearchConfigured } = useAuth()

  if (isLoading) {
    return <div className="flex h-screen items-center justify-center">Loading...</div>
  }

  // Step 1: Initial setup (create admin account)
  if (!setupCompleted) {
    return (
      <Routes>
        <Route path="*" element={<SetupPage />} />
      </Routes>
    )
  }

  // Step 2: OpenSearch wizard (shown if logged in but OpenSearch not configured)
  if (isAuthenticated && !isOpenSearchConfigured) {
    return (
      <div className="min-h-screen bg-background">
        <Header />
        <Routes>
          <Route path="*" element={<OpenSearchWizard />} />
        </Routes>
      </div>
    )
  }

  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/" element={
        <AuthRoute>
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <Dashboard />
            </main>
          </div>
        </AuthRoute>
      } />
      <Route path="/rules" element={
        <AuthRoute>
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <RulesPage />
            </main>
          </div>
        </AuthRoute>
      } />
      <Route path="/rules/new" element={
        <AuthRoute>
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <RuleEditorPage />
            </main>
          </div>
        </AuthRoute>
      } />
      <Route path="/rules/:id" element={
        <AuthRoute>
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <RuleEditorPage />
            </main>
          </div>
        </AuthRoute>
      } />
      <Route path="/correlation" element={
        <AuthRoute>
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <CorrelationRulesPage />
            </main>
          </div>
        </AuthRoute>
      } />
      <Route path="/correlation/new" element={
        <ProtectedRoute permission="manage_correlation">
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <CorrelationRuleEditorPage />
            </main>
          </div>
        </ProtectedRoute>
      } />
      <Route path="/correlation/:id" element={
        <ProtectedRoute permission="manage_correlation">
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <CorrelationRuleEditorPage />
            </main>
          </div>
        </ProtectedRoute>
      } />
      <Route path="/index-patterns" element={
        <ProtectedRoute permission="manage_index_config">
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <IndexPatternsPage />
            </main>
          </div>
        </ProtectedRoute>
      } />
      <Route path="/alerts" element={
        <AuthRoute>
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <AlertsPage />
            </main>
          </div>
        </AuthRoute>
      } />
      <Route path="/alerts/:id" element={
        <AuthRoute>
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <AlertDetailPage />
            </main>
          </div>
        </AuthRoute>
      } />
      <Route path="/live" element={
        <AuthRoute>
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <LiveAlertFeedPage />
            </main>
          </div>
        </AuthRoute>
      } />
      <Route path="/settings" element={
        <ProtectedRoute permission="manage_settings">
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <SettingsPage />
            </main>
          </div>
        </ProtectedRoute>
      } />
      <Route path="/settings/users" element={
        <ProtectedRoute permission="manage_users">
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <UsersPage />
            </main>
          </div>
        </ProtectedRoute>
      } />
      <Route path="/settings/audit" element={
        <ProtectedRoute permission="view_audit">
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <AuditLogPage />
            </main>
          </div>
        </ProtectedRoute>
      } />
      <Route path="/change-password" element={
        <AuthRoute>
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <ChangePasswordPage />
            </main>
          </div>
        </AuthRoute>
      } />
      <Route path="/account" element={
        <AuthRoute>
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <AccountPage />
            </main>
          </div>
        </AuthRoute>
      } />
      <Route path="/settings/api-keys" element={
        <AuthRoute>
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <ApiKeysPage />
            </main>
          </div>
        </AuthRoute>
      } />
      <Route path="/sigmahq" element={
        <ProtectedRoute permission="manage_sigmahq">
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <SigmaHQPage />
            </main>
          </div>
        </ProtectedRoute>
      } />
      <Route path="/health" element={
        <AuthRoute>
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <HealthPage />
            </main>
          </div>
        </AuthRoute>
      } />
      <Route path="/field-mappings" element={
        <ProtectedRoute permission="manage_index_config">
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <FieldMappingsPage />
            </main>
          </div>
        </ProtectedRoute>
      } />
      <Route path="/attack" element={
        <AuthRoute>
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <AttackMatrixPage />
            </main>
          </div>
        </AuthRoute>
      } />
      <Route path="/opensearch-wizard" element={
        <AuthRoute>
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <OpenSearchWizard />
            </main>
          </div>
        </AuthRoute>
      } />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}

export default function App() {
  return (
    <ThemeProvider defaultTheme="system" storageKey="chad-ui-theme">
      <ToastProvider>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </ToastProvider>
    </ThemeProvider>
  )
}
