/**
 * Sigma Rule Completion Provider
 *
 * Context-aware autocomplete for Sigma rules in Monaco editor.
 */

import type * as Monaco from 'monaco-editor'
import {
  SIGMA_SCHEMA,
  getAllModifiers,
  getTaxonomyFields,
  getAllTaxonomyFields,
} from './schema'

/**
 * Context types for cursor position in Sigma YAML
 */
type SigmaContextType =
  | 'root'
  | 'logsource'
  | 'logsource.category'
  | 'logsource.product'
  | 'logsource.service'
  | 'detection'
  | 'detection.selection'
  | 'detection.condition'
  | 'modifier'
  | 'status'
  | 'level'
  | 'related'
  | 'related.type'
  | 'unknown'

interface SigmaContext {
  type: SigmaContextType
  category?: string // Detected logsource category for field suggestions
  lineIndent: number
  isValuePosition: boolean
}

/**
 * Parse the document to determine the context at cursor position
 */
function getContext(
  model: Monaco.editor.ITextModel,
  position: Monaco.Position,
): SigmaContext {
  const lineContent = model.getLineContent(position.lineNumber)
  const textBeforeCursor = lineContent.substring(0, position.column - 1)

  // Calculate indentation
  const lineIndent = lineContent.search(/\S/)
  const effectiveIndent = lineIndent === -1 ? 0 : lineIndent

  // Check if cursor is after a pipe character (modifier context)
  if (textBeforeCursor.includes('|')) {
    const lastPipeIndex = textBeforeCursor.lastIndexOf('|')
    // Check if we're still in the modifier part (no colon after pipe)
    if (!textBeforeCursor.substring(lastPipeIndex).includes(':')) {
      return { type: 'modifier', lineIndent: effectiveIndent, isValuePosition: true }
    }
  }

  // Check if we're in a value position (after colon)
  const colonIndex = lineContent.indexOf(':')
  const isValuePosition = colonIndex !== -1 && position.column > colonIndex + 1

  // Parse lines above to determine context
  let currentParent: string | null = null
  let grandParent: string | null = null
  let detectedCategory: string | undefined

  // Walk backwards through lines to find parent context
  for (let lineNum = position.lineNumber - 1; lineNum >= 1; lineNum--) {
    const line = model.getLineContent(lineNum)
    const trimmedLine = line.trim()

    if (trimmedLine === '' || trimmedLine.startsWith('#')) continue

    const lineIndentLevel = line.search(/\S/)
    if (lineIndentLevel === -1) continue

    // Look for key: pattern at lower indentation levels
    const keyMatch = trimmedLine.match(/^([a-zA-Z_][a-zA-Z0-9_-]*)\s*:/)
    if (keyMatch) {
      const key = keyMatch[1]

      if (lineIndentLevel < effectiveIndent) {
        if (!currentParent) {
          currentParent = key
        } else if (!grandParent && lineIndentLevel < lineIndentLevel) {
          grandParent = key
        }
      }

      // Track category if we're in logsource
      if (key === 'category' && currentParent === 'logsource') {
        const valueMatch = trimmedLine.match(/^category\s*:\s*(.+)/)
        if (valueMatch) {
          detectedCategory = valueMatch[1].trim()
        }
      }

      // If we've found root-level key, stop
      if (lineIndentLevel === 0) {
        if (!currentParent) currentParent = key
        break
      }
    }
  }

  // Also check current line for context clues
  const currentLineKey = lineContent.trim().match(/^([a-zA-Z_][a-zA-Z0-9_-]*)\s*:/)
  const currentKey = currentLineKey ? currentLineKey[1] : null

  // Determine context type
  if (effectiveIndent === 0 || (effectiveIndent <= 2 && !currentParent)) {
    // Root level or typing a top-level key
    if (currentKey === 'status' || (currentParent === 'status' && isValuePosition)) {
      return { type: 'status', lineIndent: effectiveIndent, isValuePosition }
    }
    if (currentKey === 'level' || (currentParent === 'level' && isValuePosition)) {
      return { type: 'level', lineIndent: effectiveIndent, isValuePosition }
    }
    return { type: 'root', lineIndent: effectiveIndent, isValuePosition }
  }

  // Under logsource
  if (currentParent === 'logsource') {
    if (currentKey === 'category' && isValuePosition) {
      return { type: 'logsource.category', lineIndent: effectiveIndent, isValuePosition }
    }
    if (currentKey === 'product' && isValuePosition) {
      return { type: 'logsource.product', lineIndent: effectiveIndent, isValuePosition }
    }
    if (currentKey === 'service' && isValuePosition) {
      return { type: 'logsource.service', lineIndent: effectiveIndent, isValuePosition }
    }
    return { type: 'logsource', lineIndent: effectiveIndent, isValuePosition }
  }

  // Under detection
  if (currentParent === 'detection') {
    if (currentKey === 'condition' && isValuePosition) {
      return {
        type: 'detection.condition',
        lineIndent: effectiveIndent,
        isValuePosition,
        category: detectedCategory,
      }
    }
    return {
      type: 'detection',
      lineIndent: effectiveIndent,
      isValuePosition,
      category: detectedCategory,
    }
  }

  // Inside a detection selection (e.g., under selection:, filter:, etc.)
  if (grandParent === 'detection' || currentParent?.startsWith('selection') || currentParent?.startsWith('filter')) {
    return {
      type: 'detection.selection',
      lineIndent: effectiveIndent,
      isValuePosition,
      category: detectedCategory,
    }
  }

  // Under related
  if (currentParent === 'related') {
    if (currentKey === 'type' && isValuePosition) {
      return { type: 'related.type', lineIndent: effectiveIndent, isValuePosition }
    }
    return { type: 'related', lineIndent: effectiveIndent, isValuePosition }
  }

  // Check for status/level anywhere
  if (currentKey === 'status' && isValuePosition) {
    return { type: 'status', lineIndent: effectiveIndent, isValuePosition }
  }
  if (currentKey === 'level' && isValuePosition) {
    return { type: 'level', lineIndent: effectiveIndent, isValuePosition }
  }

  return { type: 'unknown', lineIndent: effectiveIndent, isValuePosition }
}

/**
 * Get the word range at the cursor position
 */
function getWordRange(
  model: Monaco.editor.ITextModel,
  position: Monaco.Position,
  monaco: typeof Monaco,
): Monaco.IRange {
  const word = model.getWordAtPosition(position)
  if (word) {
    return new monaco.Range(
      position.lineNumber,
      word.startColumn,
      position.lineNumber,
      word.endColumn,
    )
  }
  return new monaco.Range(
    position.lineNumber,
    position.column,
    position.lineNumber,
    position.column,
  )
}

/**
 * Create completion items from schema items
 */
function createCompletions(
  items: { key?: string; value?: string; name?: string; keyword?: string; field?: string; doc: string }[],
  kind: Monaco.languages.CompletionItemKind,
  range: Monaco.IRange,
  insertSuffix = '',
): Monaco.languages.CompletionItem[] {
  return items.map((item, index) => {
    const label = item.key || item.value || item.name || item.keyword || item.field || ''
    return {
      label,
      kind,
      insertText: label + insertSuffix,
      documentation: item.doc,
      range,
      sortText: String(index).padStart(4, '0'), // Maintain order
    }
  })
}

/**
 * Sigma Completion Provider for Monaco Editor
 */
export class SigmaCompletionProvider implements Monaco.languages.CompletionItemProvider {
  triggerCharacters = [':', '|', ' ', '\n']

  private monaco: typeof Monaco

  constructor(monaco: typeof Monaco) {
    this.monaco = monaco
  }

  provideCompletionItems(
    model: Monaco.editor.ITextModel,
    position: Monaco.Position,
  ): Monaco.languages.CompletionList {
    const context = getContext(model, position)
    const range = getWordRange(model, position, this.monaco)

    let suggestions: Monaco.languages.CompletionItem[] = []

    switch (context.type) {
      case 'root':
        // Top-level Sigma keys
        suggestions = createCompletions(
          SIGMA_SCHEMA.topLevelKeys,
          this.monaco.languages.CompletionItemKind.Property,
          range,
          ': ',
        )
        break

      case 'logsource':
        // Logsource sub-keys
        suggestions = createCompletions(
          SIGMA_SCHEMA.logsource.keys,
          this.monaco.languages.CompletionItemKind.Property,
          range,
          ': ',
        )
        break

      case 'logsource.category':
        suggestions = createCompletions(
          SIGMA_SCHEMA.logsource.category,
          this.monaco.languages.CompletionItemKind.Value,
          range,
        )
        break

      case 'logsource.product':
        suggestions = createCompletions(
          SIGMA_SCHEMA.logsource.product,
          this.monaco.languages.CompletionItemKind.Value,
          range,
        )
        break

      case 'logsource.service':
        suggestions = createCompletions(
          SIGMA_SCHEMA.logsource.service,
          this.monaco.languages.CompletionItemKind.Value,
          range,
        )
        break

      case 'detection':
        // Detection block keys (selection, filter, condition)
        suggestions = createCompletions(
          SIGMA_SCHEMA.detection.keys,
          this.monaco.languages.CompletionItemKind.Property,
          range,
          ': ',
        )
        break

      case 'detection.selection': {
        // Field names - prioritize category-specific if available
        const fields = context.category
          ? getTaxonomyFields(context.category)
          : getAllTaxonomyFields()

        if (fields.length > 0) {
          suggestions = createCompletions(
            fields,
            this.monaco.languages.CompletionItemKind.Field,
            range,
            ': ',
          )
        } else {
          // Fallback to all taxonomy fields
          suggestions = createCompletions(
            getAllTaxonomyFields(),
            this.monaco.languages.CompletionItemKind.Field,
            range,
            ': ',
          )
        }
        break
      }

      case 'detection.condition':
        // Condition keywords
        suggestions = createCompletions(
          SIGMA_SCHEMA.conditionKeywords,
          this.monaco.languages.CompletionItemKind.Keyword,
          range,
        )
        break

      case 'modifier':
        // Field modifiers
        suggestions = createCompletions(
          getAllModifiers(),
          this.monaco.languages.CompletionItemKind.Function,
          range,
        )
        break

      case 'status':
        suggestions = createCompletions(
          SIGMA_SCHEMA.status,
          this.monaco.languages.CompletionItemKind.EnumMember,
          range,
        )
        break

      case 'level':
        suggestions = createCompletions(
          SIGMA_SCHEMA.level,
          this.monaco.languages.CompletionItemKind.EnumMember,
          range,
        )
        break

      case 'related':
        suggestions = [
          {
            label: 'id',
            kind: this.monaco.languages.CompletionItemKind.Property,
            insertText: 'id: ',
            documentation: 'UUID of the related rule',
            range,
            sortText: '0000',
          },
          {
            label: 'type',
            kind: this.monaco.languages.CompletionItemKind.Property,
            insertText: 'type: ',
            documentation: 'Type of relationship',
            range,
            sortText: '0001',
          },
        ]
        break

      case 'related.type':
        suggestions = createCompletions(
          SIGMA_SCHEMA.relatedTypes,
          this.monaco.languages.CompletionItemKind.EnumMember,
          range,
        )
        break

      default:
        // Unknown context - provide top-level keys as fallback
        suggestions = createCompletions(
          SIGMA_SCHEMA.topLevelKeys,
          this.monaco.languages.CompletionItemKind.Property,
          range,
          ': ',
        )
    }

    return { suggestions }
  }
}
