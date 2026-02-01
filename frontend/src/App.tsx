import { Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { ThemeProvider } from '@/hooks/use-theme'
import { AuthProvider, useAuth } from '@/hooks/use-auth'
import { ModeProvider } from '@/hooks/useMode'
import { ToastProvider } from '@/components/ui/toast-provider'
import { AppLayout } from '@/components/AppLayout'
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
  const { setupCompleted, isLoading, isStartingUp, isAuthenticated, isOpenSearchConfigured } = useAuth()

  if (isLoading || isStartingUp) {
    return (
      <div className="flex h-screen items-center justify-center bg-background">
        <div className="text-center space-y-4">
          <div className="animate-spin h-8 w-8 border-4 border-primary border-t-transparent rounded-full mx-auto"></div>
          <p className="text-muted-foreground">
            {isStartingUp ? 'Application starting up...' : 'Loading...'}
          </p>
          {isStartingUp && (
            <p className="text-sm text-muted-foreground">
              Please wait while the backend initializes
            </p>
          )}
        </div>
      </div>
    )
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
          <AppLayout><Dashboard /></AppLayout>
        </AuthRoute>
      } />
      <Route path="/rules" element={
        <AuthRoute>
          <AppLayout><RulesPage /></AppLayout>
        </AuthRoute>
      } />
      <Route path="/rules/new" element={
        <AuthRoute>
          <AppLayout><RuleEditorPage /></AppLayout>
        </AuthRoute>
      } />
      <Route path="/rules/:id" element={
        <AuthRoute>
          <AppLayout><RuleEditorPage /></AppLayout>
        </AuthRoute>
      } />
      <Route path="/correlation" element={
        <AuthRoute>
          <AppLayout><CorrelationRulesPage /></AppLayout>
        </AuthRoute>
      } />
      <Route path="/correlation/new" element={
        <ProtectedRoute permission="manage_correlation">
          <AppLayout><CorrelationRuleEditorPage /></AppLayout>
        </ProtectedRoute>
      } />
      <Route path="/correlation/:id" element={
        <ProtectedRoute permission="manage_correlation">
          <AppLayout><CorrelationRuleEditorPage /></AppLayout>
        </ProtectedRoute>
      } />
      <Route path="/index-patterns" element={
        <ProtectedRoute permission="manage_index_config">
          <AppLayout><IndexPatternsPage /></AppLayout>
        </ProtectedRoute>
      } />
      <Route path="/alerts" element={
        <AuthRoute>
          <AppLayout><AlertsPage /></AppLayout>
        </AuthRoute>
      } />
      <Route path="/alerts/:id" element={
        <AuthRoute>
          <AppLayout><AlertDetailPage /></AppLayout>
        </AuthRoute>
      } />
      <Route path="/live" element={
        <AuthRoute>
          <AppLayout><LiveAlertFeedPage /></AppLayout>
        </AuthRoute>
      } />
      <Route path="/settings" element={
        <ProtectedRoute permission="manage_settings">
          <AppLayout><SettingsPage /></AppLayout>
        </ProtectedRoute>
      } />
      <Route path="/settings/users" element={
        <ProtectedRoute permission="manage_users">
          <AppLayout><UsersPage /></AppLayout>
        </ProtectedRoute>
      } />
      <Route path="/settings/audit" element={
        <ProtectedRoute permission="view_audit">
          <AppLayout><AuditLogPage /></AppLayout>
        </ProtectedRoute>
      } />
      <Route path="/change-password" element={
        <AuthRoute>
          <AppLayout><ChangePasswordPage /></AppLayout>
        </AuthRoute>
      } />
      <Route path="/account" element={
        <AuthRoute>
          <AppLayout><AccountPage /></AppLayout>
        </AuthRoute>
      } />
      <Route path="/settings/api-keys" element={
        <AuthRoute>
          <AppLayout><ApiKeysPage /></AppLayout>
        </AuthRoute>
      } />
      <Route path="/sigmahq" element={
        <ProtectedRoute permission="manage_sigmahq">
          <AppLayout><SigmaHQPage /></AppLayout>
        </ProtectedRoute>
      } />
      <Route path="/health" element={
        <AuthRoute>
          <AppLayout><HealthPage /></AppLayout>
        </AuthRoute>
      } />
      <Route path="/field-mappings" element={
        <ProtectedRoute permission="manage_index_config">
          <AppLayout><FieldMappingsPage /></AppLayout>
        </ProtectedRoute>
      } />
      <Route path="/attack" element={
        <AuthRoute>
          <AppLayout><AttackMatrixPage /></AppLayout>
        </AuthRoute>
      } />
      <Route path="/opensearch-wizard" element={
        <AuthRoute>
          <AppLayout><OpenSearchWizard /></AppLayout>
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
          <ModeProvider>
            <AppRoutes />
          </ModeProvider>
        </AuthProvider>
      </ToastProvider>
    </ThemeProvider>
  )
}
