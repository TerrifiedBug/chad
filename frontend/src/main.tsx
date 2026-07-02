import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { QueryClientProvider } from '@tanstack/react-query'
import { queryClient } from './lib/api'
import App from './App'
// VF console typography: Inter (body/display) + JetBrains Mono (detail layer).
// Self-hosted via @fontsource so there is no external font request.
import '@fontsource/inter/400.css'
import '@fontsource/inter/500.css'
import '@fontsource/inter/600.css'
import '@fontsource/inter/700.css'
import '@fontsource-variable/jetbrains-mono'
import './styles/globals.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter basename="/chad">
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>,
)
