import { Bell, FileText, Search, Plus, Link2, Database, Shield } from 'lucide-react'

export type EmptyStateConfig = {
  icon: typeof Bell
  title: string
  description: string
  tips?: string[]
  action?: {
    label: string
    href?: string
    icon?: typeof Plus
  }
}

export const EMPTY_STATES = {
  alerts: {
    noData: {
      icon: Bell,
      title: 'All clear!',
      description: 'No alerts have been triggered. Your rules are monitoring for threats.',
      tips: [
        'Deploy rules to start detecting threats',
        'Check index patterns are receiving data',
        'Review rule deployment status',
      ],
    },
    filtered: {
      icon: Search,
      title: 'No matching alerts',
      description: 'Try adjusting your filters to see more results.',
    },
  },
  rules: {
    noData: {
      icon: FileText,
      title: 'No detection rules yet',
      description: 'Create your first rule to start detecting threats in your data.',
      action: {
        label: 'Create Rule',
        href: '/rules/new',
        icon: Plus,
      },
      tips: [
        'Import from SigmaHQ for community rules',
        'Create custom rules for your environment',
        'Use correlation rules for complex patterns',
      ],
    },
    filtered: {
      icon: Search,
      title: 'No rules match your filters',
      description: 'Try adjusting your filters to see more results.',
    },
  },
  correlationRules: {
    noData: {
      icon: Link2,
      title: 'No correlation rules yet',
      description: 'Create correlation rules to detect multi-event attack patterns.',
      action: {
        label: 'Create Correlation Rule',
        href: '/correlation/new',
        icon: Plus,
      },
      tips: [
        'Link multiple Sigma rules together',
        'Define time windows for event sequences',
        'Set thresholds for pattern matching',
      ],
    },
    filtered: {
      icon: Search,
      title: 'No correlation rules match your filters',
      description: 'Try adjusting your filters to see more results.',
    },
  },
  indexPatterns: {
    noData: {
      icon: Database,
      title: 'No index patterns configured',
      description: 'Configure index patterns to connect CHAD to your data sources.',
      action: {
        label: 'Add Index Pattern',
        href: '/index-patterns/new',
        icon: Plus,
      },
      tips: [
        'Index patterns define where rules look for data',
        'Configure field mappings for Sigma compatibility',
        'Set up push or pull detection modes',
      ],
    },
  },
  sigmahq: {
    noData: {
      icon: Shield,
      title: 'SigmaHQ not configured',
      description: 'Connect to SigmaHQ to import community detection rules.',
      tips: [
        'SigmaHQ provides thousands of community rules',
        'Filter by category, severity, or product',
        'Auto-update rules from the repository',
      ],
    },
    filtered: {
      icon: Search,
      title: 'No SigmaHQ rules match your filters',
      description: 'Try adjusting your search or filters.',
    },
  },
} as const
