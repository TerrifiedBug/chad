// Centralized severity and status color mappings

export const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-500 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-500 text-black',
  low: 'bg-blue-500 text-white',
  informational: 'bg-gray-500 text-white',
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
