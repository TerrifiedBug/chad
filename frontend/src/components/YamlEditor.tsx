import { useEffect, useRef } from 'react'
import Editor from '@monaco-editor/react'
import { useTheme } from '@/hooks/use-theme'

interface EditorError {
  line: number
  message: string
}

interface YamlEditorProps {
  value: string
  onChange: (value: string) => void
  readOnly?: boolean
  height?: string
  errors?: EditorError[]
}

export function YamlEditor({
  value,
  onChange,
  readOnly = false,
  height = '400px',
  errors = [],
}: YamlEditorProps) {
  const { theme } = useTheme()
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const monacoRef = useRef<any>(null)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const editorRef = useRef<any>(null)

  // Determine effective theme (resolve 'system' to actual theme)
  const getEffectiveTheme = () => {
    if (theme === 'system') {
      return window.matchMedia('(prefers-color-scheme: dark)').matches
        ? 'vs-dark'
        : 'light'
    }
    return theme === 'dark' ? 'vs-dark' : 'light'
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const handleEditorDidMount = (editor: any, monaco: any) => {
    editorRef.current = editor
    monacoRef.current = monaco

    // Configure YAML language settings
    monaco.languages.setLanguageConfiguration('yaml', {
      comments: {
        lineComment: '#',
      },
      brackets: [
        ['{', '}'],
        ['[', ']'],
      ],
      autoClosingPairs: [
        { open: '{', close: '}' },
        { open: '[', close: ']' },
        { open: '"', close: '"' },
        { open: "'", close: "'" },
      ],
    })
  }

  // Update error markers when errors change
  useEffect(() => {
    if (!monacoRef.current || !editorRef.current) return

    const model = editorRef.current.getModel()
    if (!model) return

    const markers = errors.map((error) => ({
      startLineNumber: error.line,
      startColumn: 1,
      endLineNumber: error.line,
      endColumn: model.getLineMaxColumn(error.line),
      message: error.message,
      severity: monacoRef.current.MarkerSeverity.Error,
    }))

    monacoRef.current.editor.setModelMarkers(model, 'yaml-validation', markers)
  }, [errors])

  return (
    <Editor
      height={height}
      language="yaml"
      theme={getEffectiveTheme()}
      value={value}
      onChange={(val) => onChange(val || '')}
      onMount={handleEditorDidMount}
      options={{
        readOnly,
        minimap: { enabled: false },
        lineNumbers: 'on',
        scrollBeyondLastLine: false,
        automaticLayout: true,
        tabSize: 2,
        insertSpaces: true,
        wordWrap: 'on',
        fontSize: 14,
        fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
      }}
    />
  )
}
