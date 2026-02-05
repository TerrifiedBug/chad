// Centralized severity and status color mappings
import { ShieldAlert, AlertTriangle, AlertCircle, Info, LucideIcon } from 'lucide-react'

export const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-500 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-500 text-black',
  low: 'bg-blue-500 text-white',
  informational: 'bg-gray-500 text-white',
}

// Enhanced severity configuration with icons and row classes
export const SEVERITY_CONFIG: Record<string, {
  color: string
  icon: LucideIcon
  rowClass: string
  dotColor: string
}> = {
  critical: {
    color: 'bg-red-500 text-white',
    icon: ShieldAlert,
    rowClass: 'severity-row-critical',
    dotColor: 'bg-red-500',
  },
  high: {
    color: 'bg-orange-500 text-white',
    icon: AlertTriangle,
    rowClass: 'severity-row-high',
    dotColor: 'bg-orange-500',
  },
  medium: {
    color: 'bg-yellow-500 text-black',
    icon: AlertCircle,
    rowClass: 'severity-row-medium',
    dotColor: 'bg-yellow-500',
  },
  low: {
    color: 'bg-blue-500 text-white',
    icon: Info,
    rowClass: '',
    dotColor: 'bg-blue-500',
  },
  informational: {
    color: 'bg-slate-400 text-white',
    icon: Info,
    rowClass: '',
    dotColor: 'bg-slate-400',
  },
}

// Severity colors with transparency (for cards/badges with subtle backgrounds)
export const SEVERITY_COLORS_SUBTLE: Record<string, string> = {
  critical: 'bg-red-500/10 text-red-500 border-red-500/20',
  high: 'bg-orange-500/10 text-orange-500 border-orange-500/20',
  medium: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
  low: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
  informational: 'bg-gray-500/10 text-gray-500 border-gray-500/20',
}

export const STATUS_COLORS: Record<string, string> = {
  deployed: 'bg-green-600 text-white',
  undeployed: 'bg-gray-500 text-white',
  snoozed: 'bg-yellow-500 text-white',
}

export const ALERT_STATUS_COLORS: Record<string, string> = {
  new: 'bg-blue-500 text-white',
  acknowledged: 'bg-yellow-500 text-black',
  resolved: 'bg-green-500 text-white',
  false_positive: 'bg-gray-500 text-white',
}

export const ALERT_STATUS_LABELS: Record<string, string> = {
  new: 'New',
  acknowledged: 'Acknowledged',
  resolved: 'Resolved',
  false_positive: 'False Positive',
}

export function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1)
}

// User role colors (for badges and indicators)
export const ROLE_COLORS: Record<string, string> = {
  admin: 'bg-purple-500 text-white',
  analyst: 'bg-blue-500 text-white',
  viewer: 'bg-gray-500 text-white',
}

export const ROLE_COLORS_SUBTLE: Record<string, string> = {
  admin: 'bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/20',
  analyst: 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20',
  viewer: 'bg-gray-500/10 text-gray-600 dark:text-gray-400 border-gray-500/20',
}

// Detection mode colors (push/pull)
export const MODE_COLORS: Record<string, string> = {
  push: 'bg-green-500 text-white',
  pull: 'bg-blue-500 text-white',
}

export const MODE_COLORS_SUBTLE: Record<string, string> = {
  push: 'bg-green-500/10 text-green-600 dark:text-green-400 border-green-500/20',
  pull: 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20',
}

// Health status colors
export const HEALTH_COLORS: Record<string, string> = {
  healthy: 'text-green-500',
  warning: 'text-yellow-500',
  critical: 'text-red-500',
  unknown: 'text-gray-400',
}

export const HEALTH_BG_COLORS: Record<string, string> = {
  healthy: 'bg-green-500/10',
  warning: 'bg-yellow-500/10',
  critical: 'bg-red-500/10',
  unknown: 'bg-gray-500/10',
}

// Sigma rule status colors (stable/test/experimental)
export const SIGMA_STATUS_COLORS: Record<string, string> = {
  stable: 'bg-green-500 text-white',
  test: 'bg-yellow-500 text-black',
  experimental: 'bg-orange-500 text-white',
}

export const SIGMA_STATUS_COLORS_SUBTLE: Record<string, string> = {
  stable: 'bg-green-500/10 text-green-600 dark:text-green-400',
  test: 'bg-yellow-500/10 text-yellow-600 dark:text-yellow-400',
  experimental: 'bg-orange-500/10 text-orange-600 dark:text-orange-400',
}

// MISP threat level colors
export const THREAT_LEVEL_COLORS: Record<string, string> = {
  high: 'bg-red-500 text-white',
  medium: 'bg-orange-500 text-white',
  low: 'bg-yellow-500 text-black',
  undefined: 'bg-gray-500 text-white',
}

export const THREAT_LEVEL_COLORS_SUBTLE: Record<string, string> = {
  high: 'bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/20',
  medium: 'bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/20',
  low: 'bg-yellow-500/10 text-yellow-600 dark:text-yellow-400 border-yellow-500/20',
  undefined: 'bg-gray-500/10 text-gray-600 dark:text-gray-400 border-gray-500/20',
}

// Animation duration constants for consistent transitions
export const ANIMATION = {
  fast: 'duration-150',
  normal: 'duration-200',
  slow: 'duration-300',
} as const

// Animation easing constants
export const EASING = {
  default: 'ease-out',
  bounce: 'ease-[cubic-bezier(0.34,1.56,0.64,1)]',
  smooth: 'ease-in-out',
} as const
