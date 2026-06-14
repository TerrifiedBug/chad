// frontend/src/components/CommandPalette.tsx
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { GitBranch, ScrollText, Search } from 'lucide-react'
import { Dialog, DialogContent, DialogTitle } from '@/components/ui/dialog'
import { useAuth } from '@/hooks/use-auth'
import { navSections, settingsItem } from '@/components/AppRail'
import { allSettingsNavItems } from '@/config/settingsNav'
import { cn } from '@/lib/utils'

interface Command {
  id: string
  label: string
  group: string
  icon: React.ElementType
  href: string
  permission?: string
}

/**
 * ⌘K / Ctrl+K command palette: fuzzy-search pages and quick actions and jump
 * to them from the keyboard. Self-contained — owns its own open state and
 * key listener; render once near the app shell.
 */
export function CommandPalette() {
  const navigate = useNavigate()
  const { hasPermission } = useAuth()
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)

  // ⌘K / Ctrl+K toggles the palette globally.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setOpen((o) => !o)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  useEffect(() => {
    if (open) {
      setQuery('')
      setSelected(0)
    }
  }, [open])

  const commands = useMemo<Command[]>(() => {
    const navCommands: Command[] = navSections.flatMap((section) =>
      section.items.map((item) => ({
        id: `nav:${item.href}`,
        label: item.label,
        group: section.label,
        icon: item.icon,
        href: item.href,
        permission: item.permission,
      }))
    )
    navCommands.push({
      id: `nav:${settingsItem.href}`,
      label: settingsItem.label,
      group: 'System',
      icon: settingsItem.icon,
      href: settingsItem.href,
      permission: settingsItem.permission,
    })

    // Surface each settings sub-section so ⌘K can jump straight into it.
    for (const item of allSettingsNavItems) {
      navCommands.push({
        id: `nav:${item.href}`,
        label: `Settings: ${item.label}`,
        group: 'Settings',
        icon: item.icon,
        href: item.href,
        permission: item.permission ?? settingsItem.permission,
      })
    }

    const actions: Command[] = [
      { id: 'action:new-rule', label: 'New rule', group: 'Actions', icon: ScrollText, href: '/rules/new', permission: 'manage_rules' },
      { id: 'action:new-correlation', label: 'New correlation rule', group: 'Actions', icon: GitBranch, href: '/correlation/new', permission: 'manage_correlation' },
    ]

    return [...navCommands, ...actions].filter(
      (command) => !command.permission || hasPermission(command.permission)
    )
  }, [hasPermission])

  const results = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return commands
    return commands.filter(
      (c) => c.label.toLowerCase().includes(q) || c.group.toLowerCase().includes(q)
    )
  }, [commands, query])

  // Keep the selected index within range as results shrink.
  useEffect(() => {
    setSelected((s) => Math.min(s, Math.max(0, results.length - 1)))
  }, [results.length])

  const run = useCallback(
    (command?: Command) => {
      if (!command) return
      setOpen(false)
      navigate(command.href)
    },
    [navigate]
  )

  const onInputKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setSelected((s) => Math.min(s + 1, results.length - 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setSelected((s) => Math.max(s - 1, 0))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      run(results[selected])
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="overflow-hidden p-0 sm:max-w-[560px]">
        <DialogTitle className="sr-only">Command palette</DialogTitle>
        <div className="flex items-center gap-2 border-b px-3">
          <Search className="h-4 w-4 shrink-0 text-muted-foreground" />
          <input
            ref={inputRef}
            autoFocus
            value={query}
            onChange={(e) => {
              setQuery(e.target.value)
              setSelected(0)
            }}
            onKeyDown={onInputKeyDown}
            placeholder="Search pages and actions…"
            aria-label="Command palette search"
            className="h-11 w-full bg-transparent text-sm outline-none placeholder:text-muted-foreground"
          />
        </div>

        <div className="max-h-80 overflow-y-auto py-1">
          {results.length === 0 ? (
            <div className="px-3 py-6 text-center text-sm text-muted-foreground">No results</div>
          ) : (
            results.map((command, i) => {
              const Icon = command.icon
              return (
                <button
                  key={command.id}
                  type="button"
                  onMouseEnter={() => setSelected(i)}
                  onClick={() => run(command)}
                  className={cn(
                    'flex w-full items-center gap-3 px-3 py-2 text-left text-sm',
                    i === selected ? 'bg-accent text-accent-foreground' : 'text-foreground'
                  )}
                >
                  <Icon className="h-4 w-4 shrink-0 text-muted-foreground" />
                  <span className="flex-1 truncate">{command.label}</span>
                  <span className="text-xs text-muted-foreground">{command.group}</span>
                </button>
              )
            })
          )}
        </div>

        <div className="flex items-center justify-between border-t px-3 py-2 text-[11px] text-muted-foreground">
          <span>↑↓ navigate · ↵ select · esc close</span>
          <span>
            {results.length} result{results.length === 1 ? '' : 's'}
          </span>
        </div>
      </DialogContent>
    </Dialog>
  )
}
