import { describe, it, expect, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { KpiStrip, KpiTile } from '@/components/ui/kpi-tile'
import { EmptyState } from '@/components/ui/empty-state'
import { ThemeProvider } from '@/hooks/use-theme'

describe('VF UX parity idioms', () => {
  describe('KpiStrip / KpiTile', () => {
    it('renders tile labels and values', () => {
      render(
        <KpiStrip>
          <KpiTile label="Alerts Today" value={42} sublabel="100 total" tone="accent" />
          <KpiTile label="New Alerts" value={7} tone="error" />
        </KpiStrip>
      )
      expect(screen.getByText('Alerts Today')).toBeInTheDocument()
      expect(screen.getByText('42')).toBeInTheDocument()
      expect(screen.getByText('100 total')).toBeInTheDocument()
      expect(screen.getByText('New Alerts')).toBeInTheDocument()
      expect(screen.getByText('7')).toBeInTheDocument()
    })
  })

  describe('EmptyState glyph-tile', () => {
    it('renders title, description, and $-prompt tips', () => {
      render(
        <MemoryRouter>
          <EmptyState
            title="No rules yet"
            description="Create your first detection rule"
            tips={['Import from SigmaHQ', 'Write your own']}
          />
        </MemoryRouter>
      )
      expect(screen.getByText('No rules yet')).toBeInTheDocument()
      expect(screen.getByText('Create your first detection rule')).toBeInTheDocument()
      expect(screen.getByText('Import from SigmaHQ')).toBeInTheDocument()
      expect(screen.getByText('Write your own')).toBeInTheDocument()
    })
  })
})

describe('Default theme resolves to dark', () => {
  beforeEach(() => {
    localStorage.clear()
    document.documentElement.classList.remove('light', 'dark')
  })

  it('applies the dark class on <html> when no preference is stored', () => {
    // No stored "chad-ui-theme" -> the provider defaults to the dark console.
    render(
      <ThemeProvider>
        <div>app</div>
      </ThemeProvider>
    )
    expect(document.documentElement.classList.contains('dark')).toBe(true)
    expect(document.documentElement.classList.contains('light')).toBe(false)
  })
})
