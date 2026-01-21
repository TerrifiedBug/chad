import { Sun, Moon, Monitor } from 'lucide-react'
import { useTheme } from '@/hooks/use-theme'

type Theme = 'light' | 'dark' | 'system'

const themeConfig: Record<Theme, { icon: typeof Sun; label: string; next: Theme }> = {
  light: { icon: Sun, label: 'Light mode', next: 'dark' },
  dark: { icon: Moon, label: 'Dark mode', next: 'system' },
  system: { icon: Monitor, label: 'System mode', next: 'light' },
}

export function ThemeToggle() {
  const { theme, setTheme } = useTheme()
  const config = themeConfig[theme]
  const Icon = config.icon

  return (
    <button
      onClick={() => setTheme(config.next)}
      className="inline-flex items-center justify-center rounded-md p-2 text-sm font-medium ring-offset-background transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
      title={config.label}
    >
      <Icon className="h-5 w-5" />
      <span className="sr-only">{config.label}</span>
    </button>
  )
}
