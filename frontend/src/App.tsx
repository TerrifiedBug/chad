import { Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { ThemeProvider } from '@/hooks/use-theme'
import { AuthProvider, useAuth } from '@/hooks/use-auth'
import { ToastProvider } from '@/components/ui/toast-provider'
import { Header } from '@/components/Header'
import { AdminRoute } from '@/components/AdminRoute'
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

function ProtectedRoute({ children }: { children: React.ReactNode }) {
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
        <ProtectedRoute>
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <Dashboard />
            </main>
          </div>
        </ProtectedRoute>
      } />
      <Route path="/rules" element={
        <ProtectedRoute>
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <RulesPage />
            </main>
          </div>
        </ProtectedRoute>
      } />
      <Route path="/rules/new" element={
        <ProtectedRoute>
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <RuleEditorPage />
            </main>
          </div>
        </ProtectedRoute>
      } />
      <Route path="/rules/:id" element={
        <ProtectedRoute>
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <RuleEditorPage />
            </main>
          </div>
        </ProtectedRoute>
      } />
      <Route path="/index-patterns" element={
        <ProtectedRoute>
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <IndexPatternsPage />
            </main>
          </div>
        </ProtectedRoute>
      } />
      <Route path="/alerts" element={
        <ProtectedRoute>
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <AlertsPage />
            </main>
          </div>
        </ProtectedRoute>
      } />
      <Route path="/alerts/:id" element={
        <ProtectedRoute>
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <AlertDetailPage />
            </main>
          </div>
        </ProtectedRoute>
      } />
      <Route path="/settings" element={
        <AdminRoute>
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <SettingsPage />
            </main>
          </div>
        </AdminRoute>
      } />
      <Route path="/settings/users" element={
        <AdminRoute>
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <UsersPage />
            </main>
          </div>
        </AdminRoute>
      } />
      <Route path="/settings/audit" element={
        <AdminRoute>
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <AuditLogPage />
            </main>
          </div>
        </AdminRoute>
      } />
      <Route path="/change-password" element={
        <ProtectedRoute>
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <ChangePasswordPage />
            </main>
          </div>
        </ProtectedRoute>
      } />
      <Route path="/settings/api-keys" element={
        <ProtectedRoute>
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <ApiKeysPage />
            </main>
          </div>
        </ProtectedRoute>
      } />
      <Route path="/sigmahq" element={
        <ProtectedRoute>
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <SigmaHQPage />
            </main>
          </div>
        </ProtectedRoute>
      } />
      <Route path="/health" element={
        <AdminRoute>
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <HealthPage />
            </main>
          </div>
        </AdminRoute>
      } />
      <Route path="/field-mappings" element={
        <AdminRoute>
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <FieldMappingsPage />
            </main>
          </div>
        </AdminRoute>
      } />
      <Route path="/opensearch-wizard" element={
        <ProtectedRoute>
          <div className="min-h-screen bg-background">
            <Header />
            <main className="px-6 py-8">
              <OpenSearchWizard />
            </main>
          </div>
        </ProtectedRoute>
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
