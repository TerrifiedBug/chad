import { Routes, Route, Navigate } from 'react-router-dom'
import { ThemeProvider } from '@/hooks/use-theme'
import { AuthProvider, useAuth } from '@/hooks/use-auth'
import { Header } from '@/components/Header'
import SetupPage from '@/pages/Setup'
import LoginPage from '@/pages/Login'
import OpenSearchWizard from '@/pages/OpenSearchWizard'
import RulesPage from '@/pages/Rules'
import RuleEditorPage from '@/pages/RuleEditor'
import IndexPatternsPage from '@/pages/IndexPatterns'

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth()

  if (isLoading) {
    return <div className="flex h-screen items-center justify-center">Loading...</div>
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
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
              <h1 className="text-2xl font-bold">Welcome to CHAD</h1>
              <p className="text-muted-foreground mt-2">
                Select <strong>Rules</strong> to manage detection rules or{' '}
                <strong>Index Patterns</strong> to configure target indices.
              </p>
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
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}

export default function App() {
  return (
    <ThemeProvider defaultTheme="system" storageKey="chad-ui-theme">
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </ThemeProvider>
  )
}
