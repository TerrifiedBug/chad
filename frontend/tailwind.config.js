/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ["class"],
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        // VF console type system. CSS vars are set in globals.css so the same
        // stack resolves whether referenced via Tailwind or raw CSS.
        sans: ["var(--font-sans)", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["var(--font-mono)", "ui-monospace", "SFMono-Regular", "monospace"],
        display: ["var(--font-display)", "ui-sans-serif", "system-ui", "sans-serif"],
      },
      colors: {
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
        popover: {
          DEFAULT: "hsl(var(--popover))",
          foreground: "hsl(var(--popover-foreground))",
        },
        // ── VF "v2 console" tokens (additive) ──────────────────────────────
        // Backed by raw hex CSS vars (not HSL channels), so they read as
        // `bg-bg-2`, `border-line`, `text-fg-2`, `bg-accent-soft`,
        // `text-status-error`, etc. Defined per-theme in globals.css; in the
        // light/Classic themes they fall back to the existing semantic look.
        bg: {
          DEFAULT: "var(--bg)",
          1: "var(--bg-1)",
          2: "var(--bg-2)",
          3: "var(--bg-3)",
          4: "var(--bg-4)",
        },
        line: {
          DEFAULT: "var(--line)",
          2: "var(--line-2)",
          3: "var(--line-3)",
        },
        fg: {
          DEFAULT: "var(--fg)",
          1: "var(--fg-1)",
          2: "var(--fg-2)",
          3: "var(--fg-3)",
        },
        "accent-brand": {
          DEFAULT: "var(--accent-brand)",
          2: "var(--accent-brand-2)",
          soft: "var(--accent-brand-soft)",
          line: "var(--accent-brand-line)",
        },
        status: {
          healthy: "var(--status-healthy)",
          "healthy-bg": "var(--status-healthy-bg)",
          "healthy-foreground": "var(--status-healthy-foreground)",
          degraded: "var(--status-degraded)",
          "degraded-bg": "var(--status-degraded-bg)",
          "degraded-foreground": "var(--status-degraded-foreground)",
          error: "var(--status-error)",
          "error-bg": "var(--status-error-bg)",
          "error-foreground": "var(--status-error-foreground)",
          neutral: "var(--status-neutral)",
          "neutral-bg": "var(--status-neutral-bg)",
          "neutral-foreground": "var(--status-neutral-foreground)",
          info: "var(--status-info)",
          "info-bg": "var(--status-info-bg)",
          "info-foreground": "var(--status-info-foreground)",
        },
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 1px)",
        sm: "max(calc(var(--radius) - 1px), 1px)",
      },
    },
  },
  plugins: [require("tailwindcss-animate")],
}
