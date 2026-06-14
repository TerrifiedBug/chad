import { useSyncExternalStore } from 'react'
import type { DeployProgressMessage, DeployProgressStatus } from '@/lib/api'

// Per-rule row tracked during a bulk deploy.
export type DeployProgressRow = {
  ruleId: string
  ruleTitle: string
  status: DeployProgressStatus
  error?: string | null
}

export type DeployProgressState = {
  // True once a bulk deploy is in flight (panel is visible). Set by startBatch().
  active: boolean
  batchId: string | null
  rows: DeployProgressRow[]
}

// Module-level singleton store. No external state library — mirrors the
// "open a /ws socket and dispatch by message.type" pattern already used by
// SystemLogs/Health, but shared so the persistent panel survives navigation.
const INITIAL_STATE: DeployProgressState = { active: false, batchId: null, rows: [] }

let state: DeployProgressState = INITIAL_STATE
const listeners = new Set<() => void>()

function emit() {
  for (const l of listeners) l()
}

function setState(next: DeployProgressState) {
  state = next
  emit()
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

function getSnapshot(): DeployProgressState {
  return state
}

/**
 * Begin tracking a bulk deploy. Seeds one "queued" row per rule so the panel
 * shows immediately, before the first WS transition arrives.
 */
export function startBatch(rules: { id: string; title: string }[], batchId?: string | null) {
  setState({
    active: true,
    batchId: batchId ?? null,
    rows: rules.map((r) => ({ ruleId: r.id, ruleTitle: r.title, status: 'queued' as DeployProgressStatus })),
  })
}

/**
 * Apply a single deploy_progress transition. Upserts the row (the backend may
 * emit a transition for a rule we didn't seed, e.g. on reconnect).
 */
export function applyProgress(msg: DeployProgressMessage) {
  // Ignore messages for a different batch once one is active.
  if (state.active && state.batchId && msg.batch_id && msg.batch_id !== state.batchId) {
    return
  }
  const existing = state.rows.find((r) => r.ruleId === msg.rule_id)
  let rows: DeployProgressRow[]
  if (existing) {
    rows = state.rows.map((r) =>
      r.ruleId === msg.rule_id
        ? { ...r, ruleTitle: msg.rule_title || r.ruleTitle, status: msg.status, error: msg.error }
        : r
    )
  } else {
    rows = [
      ...state.rows,
      { ruleId: msg.rule_id, ruleTitle: msg.rule_title, status: msg.status, error: msg.error },
    ]
  }
  setState({
    active: true,
    batchId: state.batchId ?? msg.batch_id ?? null,
    rows,
  })
}

/** Dismiss/clear the panel (e.g. user closes it, or a new batch begins). */
export function clearProgress() {
  setState(INITIAL_STATE)
}

// Derived helpers (pure, safe to call in render).
export function isBatchComplete(s: DeployProgressState): boolean {
  if (!s.active || s.rows.length === 0) return false
  return s.rows.every((r) => r.status === 'success' || r.status === 'failed')
}

export function countByStatus(s: DeployProgressState) {
  let success = 0
  let failed = 0
  let inProgress = 0
  for (const r of s.rows) {
    if (r.status === 'success') success++
    else if (r.status === 'failed') failed++
    else inProgress++
  }
  return { success, failed, inProgress, total: s.rows.length }
}

/** React hook: subscribe to the deploy-progress store. */
export function useDeployProgress(): DeployProgressState {
  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot)
}

// --- Test-only escape hatch -------------------------------------------------
// Lets tests dispatch a raw deploy_progress message without standing up a WS.
export const __deployProgressStore = {
  applyProgress,
  startBatch,
  clearProgress,
  reset: () => setState(INITIAL_STATE),
  getState: () => state,
}
