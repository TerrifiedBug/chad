/**
 * Sigma Language Features for Monaco Editor
 *
 * Registers autocomplete and hover providers for Sigma rule YAML editing.
 */

import type * as Monaco from 'monaco-editor'
import { SigmaCompletionProvider } from './completion-provider'
import { SigmaHoverProvider } from './hover-provider'

// Track if providers have been registered to avoid duplicates
let isRegistered = false

/**
 * Register Sigma language features with Monaco editor.
 * Should be called once when the editor mounts.
 *
 * @param monaco - The Monaco editor instance
 */
export function registerSigmaLanguageFeatures(monaco: typeof Monaco): void {
  if (isRegistered) {
    return
  }

  // Register completion provider for YAML language
  monaco.languages.registerCompletionItemProvider('yaml', new SigmaCompletionProvider(monaco))

  // Register hover provider for YAML language
  monaco.languages.registerHoverProvider('yaml', new SigmaHoverProvider(monaco))

  isRegistered = true
}

// Re-export for convenience
export { SigmaCompletionProvider } from './completion-provider'
export { SigmaHoverProvider } from './hover-provider'
export { SIGMA_SCHEMA, findDocumentation } from './schema'
