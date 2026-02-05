import { createContext, useContext, useEffect, useState } from "react"

type Theme = "dark" | "light" | "system"
type ColorPalette = "sentinel" | "classic"

type ThemeProviderProps = {
  children: React.ReactNode
  defaultTheme?: Theme
  defaultPalette?: ColorPalette
  storageKey?: string
  paletteStorageKey?: string
}

type ThemeProviderState = {
  theme: Theme
  setTheme: (theme: Theme) => void
  palette: ColorPalette
  setPalette: (palette: ColorPalette) => void
}

const initialState: ThemeProviderState = {
  theme: "system",
  setTheme: () => null,
  palette: "sentinel",
  setPalette: () => null,
}

const ThemeProviderContext = createContext<ThemeProviderState>(initialState)

export function ThemeProvider({
  children,
  defaultTheme = "system",
  defaultPalette = "sentinel",
  storageKey = "chad-ui-theme",
  paletteStorageKey = "chad-ui-palette",
  ...props
}: ThemeProviderProps) {
  const [theme, setTheme] = useState<Theme>(
    () => (localStorage.getItem(storageKey) as Theme) || defaultTheme
  )
  const [palette, setPalette] = useState<ColorPalette>(
    () => (localStorage.getItem(paletteStorageKey) as ColorPalette) || defaultPalette
  )

  useEffect(() => {
    const root = window.document.documentElement

    root.classList.remove("light", "dark")

    if (theme === "system") {
      const systemTheme = window.matchMedia("(prefers-color-scheme: dark)")
        .matches
        ? "dark"
        : "light"

      root.classList.add(systemTheme)
      return
    }

    root.classList.add(theme)
  }, [theme])

  // Apply palette class
  useEffect(() => {
    const root = window.document.documentElement
    root.classList.remove("palette-sentinel", "palette-classic")
    if (palette === "classic") {
      root.classList.add("palette-classic")
    }
  }, [palette])

  const value = {
    theme,
    setTheme: (theme: Theme) => {
      localStorage.setItem(storageKey, theme)
      setTheme(theme)
    },
    palette,
    setPalette: (palette: ColorPalette) => {
      localStorage.setItem(paletteStorageKey, palette)
      setPalette(palette)
    },
  }

  return (
    <ThemeProviderContext.Provider {...props} value={value}>
      {children}
    </ThemeProviderContext.Provider>
  )
}

export function useTheme() {
  const context = useContext(ThemeProviderContext)
  if (context === undefined) {
    throw new Error("useTheme must be used within a ThemeProvider")
  }
  return context
}
