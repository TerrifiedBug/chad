import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

// Mutable pathname so each test can place the rail on a different route.
const state = { pathname: '/' }
vi.mock('react-router-dom', () => ({
  useLocation: () => ({ pathname: state.pathname }),
  useNavigate: () => vi.fn(),
  Link: ({ to, children, ...rest }: { to: string; children: React.ReactNode }) => (
    <a href={to} {...rest}>
      {children}
    </a>
  ),
}))
vi.mock('@tanstack/react-query', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@tanstack/react-query')>()
  return { ...actual, useQuery: () => ({ data: undefined }) }
})
vi.mock('@/hooks/use-auth', () => ({ useAuth: () => ({ hasPermission: () => true }) }))
vi.mock('@/hooks/use-version', () => ({ useVersion: () => ({ version: '0.9.1' }) }))

import { AppRail, settingsItem } from '@/components/AppRail'
import { settingsNavGroups as groups } from '@/config/settingsNav'

describe('settingsNav config', () => {
  it('every section has a /settings/<id> href and unique ids', () => {
    const ids = new Set<string>()
    for (const group of groups) {
      for (const item of group.items) {
        expect(item.href).toBe(`/settings/${item.id}`)
        expect(ids.has(item.id)).toBe(false)
        ids.add(item.id)
      }
    }
    expect(ids.size).toBeGreaterThan(10)
  })
})

describe('AppRail settings slide-in', () => {
  it('shows the product logo (not the back button) on app routes', () => {
    state.pathname = '/'
    render(<AppRail expanded onExpandedChange={() => {}} />)
    expect(screen.getByLabelText('CHAD home')).toBeInTheDocument()
    expect(screen.queryByLabelText('Back to app')).toBeNull()
    expect(screen.getByText('Dashboard')).toBeInTheDocument()
  })

  it('swaps to the back-to-app affordance + settings nav on /settings routes', () => {
    state.pathname = '/settings/general'
    render(<AppRail expanded onExpandedChange={() => {}} />)
    expect(screen.getByLabelText('Back to app')).toBeInTheDocument()
    expect(screen.queryByLabelText('CHAD home')).toBeNull()
    // Settings sections are present in the panel.
    expect(screen.getByText('General')).toBeInTheDocument()
    expect(screen.getByText('Threat Intel')).toBeInTheDocument()
  })
})

// Guard the AppRail export the CommandPalette + redirects depend on.
describe('AppRail exports', () => {
  it('keeps settingsItem pointed at /settings', () => {
    expect(settingsItem.href).toBe('/settings')
  })
})
