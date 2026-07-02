import { lazy, Suspense } from 'react'
import { Routes, Route, Navigate, useLocation, useSearchParams } from 'react-router-dom'
import { ThemeProvider } from '@/hooks/use-theme'
import { AuthProvider, useAuth } from '@/hooks/use-auth'
import { ModeProvider } from '@/hooks/useMode'
import { OpenSearchStatusProvider } from '@/contexts/OpenSearchStatus'
import { ToastProvider } from '@/components/ui/toast-provider'
import { AppLayout } from '@/components/AppLayout'
import { AppHeader } from '@/components/AppHeader'
import { ProtectedRoute } from '@/components/protected-route'
import SetupPage from '@/pages/Setup'
import LoginPage from '@/pages/Login'
import OpenSearchWizard from '@/pages/OpenSearchWizard'
import Dashboard from '@/pages/Dashboard'
import RulesPage from '@/pages/Rules'
const RuleEditorPage = lazy(() => import('@/pages/RuleEditor'))
import IndexPatternsPage from '@/pages/IndexPatterns'
import IndexPatternDetailPage from '@/pages/IndexPatternDetail'
import AlertsPage from '@/pages/Alerts'
import AlertDetailPage from '@/pages/AlertDetail'
import CasesPage from '@/pages/Cases'
import CaseDetailPage from '@/pages/CaseDetail'
import SettingsHub from '@/pages/SettingsHub'
import SettingsSection from '@/pages/settings/SettingsSection'
import ChangePasswordPage from '@/pages/ChangePassword'
import ApiKeysPage from '@/pages/ApiKeys'
const OrganizationsPage = lazy(() => import('@/pages/Organizations'))
const ReportsPage = lazy(() => import('@/pages/Reports'))
const SigmaHQPage = lazy(() => import('@/pages/SigmaHQ'))
const MISPPage = lazy(() => import('@/pages/MISP'))
const HealthPage = lazy(() => import('@/pages/Health'))
const FieldMappingsPage = lazy(() => import('@/pages/FieldMappings'))
const AttackMatrixPage = lazy(() => import('@/pages/AttackMatrix'))
import AccountPage from '@/pages/Account'
const CorrelationRuleEditorPage = lazy(() => import('@/pages/CorrelationRuleEditor'))
const LiveAlertFeedPage = lazy(() => import('@/pages/LiveAlertFeed'))
const IOCMatchesPage = lazy(() => import('@/pages/IOCMatches'))
import ApprovalsPage from '@/pages/Approvals'
const EnvironmentsPage = lazy(() => import('@/pages/Environments'))
const EnvironmentDetailPage = lazy(() => import('@/pages/EnvironmentDetail'))

function AuthRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading, user, delegatedAuth, accountInactive } = useAuth()
  const location = useLocation()

  if (isLoading) {
    return <div className="flex h-screen items-center justify-center">Loading...</div>
  }

  if (!isAuthenticated) {
    if (accountInactive) {
      // A delegated 403: the account is deactivated and no redirect will fire.
      // Show a terminal message instead of the "Redirecting..." dead-end.
      return (
        <div className="flex h-screen items-center justify-center">
          Your account has been deactivated. Contact your administrator for access.
        </div>
      )
    }
    if (delegatedAuth) {
      // The api client's 401 handler has already issued a full-page redirect
      // to the VF login; don't ping-pong with the hidden /login route.
      return <div className="flex h-screen items-center justify-center">Redirecting to sign-in...</div>
    }
    return <Navigate to="/login" replace />
  }

  // Force password change for local users who must change their password
  if (user?.must_change_password && location.pathname !== '/change-password') {
    return <Navigate to="/change-password" replace />
  }

  return <>{children}</>
}

// Legacy redirect: /settings/hub?tab=X (+ optional subtab) → /settings/X.
function SettingsHubRedirect() {
  const [params] = useSearchParams()
  const tab = params.get('tab')
  if (tab) {
    const subtab = params.get('subtab')
    return <Navigate to={`/settings/${tab}${subtab ? `?subtab=${subtab}` : ''}`} replace />
  }
  return <Navigate to="/settings" replace />
}

export function AppRoutes() {
  const { setupCompleted, isLoading, isStartingUp, connectionFailed, isAuthenticated, isOpenSearchConfigured, retryConnection, delegatedAuth } = useAuth()

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

  // Connection failed after all retries - show error with retry button
  if (connectionFailed) {
    return (
      <div className="flex h-screen items-center justify-center bg-background">
        <div className="text-center space-y-4 max-w-md px-4">
          <div className="h-12 w-12 rounded-full bg-destructive/10 flex items-center justify-center mx-auto">
            <svg className="h-6 w-6 text-destructive" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
          <h2 className="text-xl font-semibold">Unable to Connect</h2>
          <p className="text-muted-foreground">
            Could not connect to the backend server. The server may still be starting up or may be unavailable.
          </p>
          <button
            onClick={retryConnection}
            className="inline-flex items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition-colors"
          >
            Retry Connection
          </button>
        </div>
      </div>
    )
  }

  // Step 1: Initial setup (create admin account) — never shown in delegated
  // (suite) mode, where VectorFlow owns onboarding for the whole suite.
  if (!setupCompleted && !delegatedAuth) {
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
        <AppHeader />
        <main className="px-6 py-8 mx-auto max-w-screen-2xl">
          <Routes>
            <Route path="*" element={<OpenSearchWizard />} />
          </Routes>
        </main>
      </div>
    )
  }

  return (
    <Routes>
      {/* Delegated (suite) mode: VectorFlow owns login at the origin root. */}
      <Route path="/login" element={delegatedAuth ? <Navigate to="/" replace /> : <LoginPage />} />
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
      {/* Redirect old /correlation URL to unified Rules page with tab */}
      <Route path="/correlation" element={<Navigate to="/rules?tab=correlation" replace />} />
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
      <Route path="/index-patterns/new" element={
        <ProtectedRoute permission="manage_index_config">
          <AppLayout><IndexPatternDetailPage /></AppLayout>
        </ProtectedRoute>
      } />
      <Route path="/index-patterns/:id" element={
        <ProtectedRoute permission="manage_index_config">
          <AppLayout><IndexPatternDetailPage /></AppLayout>
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
      <Route path="/ioc-matches" element={
        <AuthRoute>
          <AppLayout><IOCMatchesPage /></AppLayout>
        </AuthRoute>
      } />
      <Route path="/cases" element={
        <AuthRoute>
          <AppLayout><CasesPage /></AppLayout>
        </AuthRoute>
      } />
      <Route path="/reports" element={
        <AuthRoute>
          <AppLayout><ReportsPage /></AppLayout>
        </AuthRoute>
      } />
      <Route path="/cases/:id" element={
        <AuthRoute>
          <AppLayout><CaseDetailPage /></AppLayout>
        </AuthRoute>
      } />
      <Route path="/approvals" element={
        <AuthRoute>
          <AppLayout><ApprovalsPage /></AppLayout>
        </AuthRoute>
      } />
      <Route path="/environments" element={
        <ProtectedRoute permission="manage_environments">
          <AppLayout><EnvironmentsPage /></AppLayout>
        </ProtectedRoute>
      } />
      <Route path="/environments/:id" element={
        <ProtectedRoute permission="manage_environments">
          <AppLayout><EnvironmentDetailPage /></AppLayout>
        </ProtectedRoute>
      } />
      <Route path="/live" element={
        <AuthRoute>
          <AppLayout><LiveAlertFeedPage /></AppLayout>
        </AuthRoute>
      } />
      {/* Settings overview grid. */}
      <Route path="/settings" element={
        <ProtectedRoute permission="manage_settings">
          <AppLayout><SettingsHub /></AppLayout>
        </ProtectedRoute>
      } />
      {/* Legacy /settings/hub?tab=X → /settings/X (keeps old links + bookmarks). */}
      <Route path="/settings/hub" element={<SettingsHubRedirect />} />
      {/* Permissions opens the Users page's roles subtab. */}
      <Route path="/settings/permissions" element={<Navigate to="/settings/users?subtab=roles" replace />} />
      {/* Delegated mode: VF owns identity — hide CHAD's SSO provider CRUD. */}
      {delegatedAuth && (
        <Route path="/settings/sso" element={<Navigate to="/settings" replace />} />
      )}
      {/* Per-section route (general, security, ti, users, audit, …). The static
          /settings/api-keys route below still wins over this dynamic segment. */}
      <Route path="/settings/:section" element={
        <ProtectedRoute permission="manage_settings">
          <AppLayout><SettingsSection /></AppLayout>
        </ProtectedRoute>
      } />
      <Route path="/change-password" element={
        delegatedAuth ? <Navigate to="/account" replace /> : (
          <AuthRoute>
            <AppLayout><ChangePasswordPage /></AppLayout>
          </AuthRoute>
        )
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
      <Route path="/settings/organizations" element={
        <ProtectedRoute permission="manage_users">
          <AppLayout><OrganizationsPage /></AppLayout>
        </ProtectedRoute>
      } />
      <Route path="/sigmahq" element={
        <ProtectedRoute permission="manage_sigmahq">
          <AppLayout><SigmaHQPage /></AppLayout>
        </ProtectedRoute>
      } />
      <Route path="/misp" element={
        <ProtectedRoute permission="manage_rules">
          <AppLayout><MISPPage /></AppLayout>
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
    <ThemeProvider defaultTheme="dark" storageKey="chad-ui-theme">
      <ToastProvider>
        <AuthProvider>
          <OpenSearchStatusProvider>
            <ModeProvider>
              <Suspense fallback={
                <div className="flex h-screen items-center justify-center bg-background">
                  <div className="animate-spin h-8 w-8 border-4 border-primary border-t-transparent rounded-full" />
                </div>
              }>
                <AppRoutes />
              </Suspense>
            </ModeProvider>
          </OpenSearchStatusProvider>
        </AuthProvider>
      </ToastProvider>
    </ThemeProvider>
  )
}
