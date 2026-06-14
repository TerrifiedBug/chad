import { useSyncExternalStore } from 'react'
import type { Environment } from '@/lib/api'

// Active-environment store. Holds the id of the environment the UI is currently
// scoped to (the "active env"); this id is sent as the X-CHAD-Environment header
// on every api request so the backend scopes deployment state + deploy targets.
//
// Module-level singleton with useSyncExternalStore, mirroring
// components/rules/deploy-progress-store.ts. No external state library.
//
// Persistence: the selected id is mirrored to localStorage so a reload keeps the
// active env. When the persisted id is no longer in the user's environment list
// (e.g. it belonged to another team, or was deleted), we auto-fall back to the
// team default (is_default) so we never scope to a stale cross-team env.

const STORAGE_KEY = 'chad-active-environment'

// Read the persisted id once at module load (guarded for non-browser/test envs).
function readPersisted(): string | null {
  try {
    return window.localStorage.getItem(STORAGE_KEY)
  } catch {
    return null
  }
}

function writePersisted(id: string | null): void {
  try {
    if (id) {
      window.localStorage.setItem(STORAGE_KEY, id)
    } else {
      window.localStorage.removeItem(STORAGE_KEY)
    }
  } catch {
    // localStorage unavailable (private mode / SSR) — header just stays absent,
    // which the backend treats as "use the default env".
  }
}

let selectedEnvironmentId: string | null = readPersisted()
const listeners = new Set<() => void>()

function emit() {
  for (const l of listeners) l()
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

function getSnapshot(): string | null {
  return selectedEnvironmentId
}

/**
 * Plain getter for non-React callers (the api client reads this to attach the
 * X-CHAD-Environment header). Returns null when no env is selected, in which
 * case the header is omitted and the backend falls back to the default env.
 */
export function getActiveEnvironmentId(): string | null {
  return selectedEnvironmentId
}

/**
 * Set the active environment. Persists to localStorage and notifies subscribers
 * (so the header + any env-scoped views update). Pass null to clear.
 */
export function setActiveEnvironmentId(id: string | null): void {
  if (id === selectedEnvironmentId) return
  selectedEnvironmentId = id
  writePersisted(id)
  emit()
}

/**
 * Reconcile the persisted selection against the user's current environment list.
 * Called whenever the env list (re)loads — e.g. on login or after a team change.
 *
 *  - If the current selection is still present in the list, keep it.
 *  - Otherwise auto-select the team default (is_default), else the first env.
 *  - If the list is empty, clear the selection.
 *
 * This is the "on team change, auto-select the team default" behaviour: a team
 * switch changes which envs the API returns, so the prior selection drops out of
 * the list and we fall back to that team's default.
 */
export function reconcileActiveEnvironment(environments: Environment[]): void {
  if (environments.length === 0) {
    setActiveEnvironmentId(null)
    return
  }
  const stillValid =
    selectedEnvironmentId != null &&
    environments.some((e) => e.id === selectedEnvironmentId)
  if (stillValid) return

  const fallback = environments.find((e) => e.is_default) ?? environments[0]
  setActiveEnvironmentId(fallback.id)
}

/** React hook: subscribe to the active-environment id. */
export function useActiveEnvironmentId(): string | null {
  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot)
}

// --- Test-only escape hatch -------------------------------------------------
export const __environmentStore = {
  get: getActiveEnvironmentId,
  set: setActiveEnvironmentId,
  reconcile: reconcileActiveEnvironment,
  reset: () => setActiveEnvironmentId(null),
}
