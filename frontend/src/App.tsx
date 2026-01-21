import { Routes, Route, Navigate } from 'react-router-dom'
import { ThemeProvider } from '@/hooks/use-theme'
import { AuthProvider, useAuth } from '@/hooks/use-auth'
import SetupPage from '@/pages/Setup'
import LoginPage from '@/pages/Login'

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
  const { setupCompleted, isLoading } = useAuth()

  if (isLoading) {
    return <div className="flex h-screen items-center justify-center">Loading...</div>
  }

  if (!setupCompleted) {
    return (
      <Routes>
        <Route path="*" element={<SetupPage />} />
      </Routes>
    )
  }

  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/" element={
        <ProtectedRoute>
          <div className="p-8">
            <h1 className="text-2xl font-bold">Welcome to CHAD</h1>
            <p className="text-muted-foreground mt-2">Dashboard coming soon...</p>
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
