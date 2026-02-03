/**
 * Sigma Rule Hover Provider
 *
 * Provides inline documentation for Sigma keywords and values on hover.
 */

import type * as Monaco from 'monaco-editor'
import { findDocumentation, type SchemaItem } from './schema'

/**
 * Format documentation as Markdown for hover display
 */
function formatDocumentation(item: SchemaItem): string {
  const parts: string[] = []

  // Get the label (key, value, name, keyword, or field)
  const label = item.key || item.value || item.name || item.keyword || item.field

  // Add header with label
  if (label) {
    parts.push(`**${label}**`)
    parts.push('')
  }

  // Add description
  parts.push(item.doc)

  // Add required indicator
  if (item.required !== undefined) {
    parts.push('')
    parts.push(item.required ? '*Required field*' : '*Optional field*')
  }

  // Add example if available
  if (item.example) {
    parts.push('')
    parts.push('**Example:**')
    parts.push('```yaml')
    parts.push(item.example.replace(/\\n/g, '\n'))
    parts.push('```')
  }

  return parts.join('\n')
}

/**
 * Sigma Hover Provider for Monaco Editor
 */
export class SigmaHoverProvider implements Monaco.languages.HoverProvider {
  private monaco: typeof Monaco

  constructor(monaco: typeof Monaco) {
    this.monaco = monaco
  }

  provideHover(
    model: Monaco.editor.ITextModel,
    position: Monaco.Position,
  ): Monaco.languages.Hover | null {
    const word = model.getWordAtPosition(position)
    if (!word) return null

    const wordText = word.word

    // Look up documentation for the word
    const docItem = findDocumentation(wordText)
    if (!docItem) return null

    const formattedDoc = formatDocumentation(docItem)

    return {
      contents: [{ value: formattedDoc }],
      range: new this.monaco.Range(
        position.lineNumber,
        word.startColumn,
        position.lineNumber,
        word.endColumn,
      ),
    }
  }
}
