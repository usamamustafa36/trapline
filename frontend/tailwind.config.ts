import type { Config } from "tailwindcss";

/**
 * Trapline // "Carbon Neon" — Hack-The-Box-inspired tactical design tokens.
 * Deep carbon-navy substrate lit by a signature neon-green core, cut with azure
 * (info), emerald (operational), red (threat) and a violet categorical accent.
 * (Token NAMES are kept stable so components re-theme without churn — only the
 * VALUES moved from the old "Midnight Glass" violet system to this green core.)
 */
const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        void: "#070B12",
        base: "#0B111C", // page substrate — carbon navy
        panel: "#111A28", // card surface
        "panel-2": "#152134",
        elevated: "#1B2A40",
        line: "#243449",
        "line-bright": "#33475F",
        muted: "#6C82A0",
        dim: "#A2B6D2", // HTB-style muted-light body text
        fg: "#E8F1FA",
        signal: {
          DEFAULT: "#9FEF00", // neon lime — primary / brand
          soft: "#C2FF57",
          dim: "#7BC400",
        },
        ops: {
          DEFAULT: "#3DE07A", // emerald — operational / online
          soft: "#7CF0A6",
          dim: "#20B85D",
        },
        recon: {
          DEFAULT: "#54AEFF", // azure — info / recon
          soft: "#93C9FF",
        },
        hostile: {
          DEFAULT: "#FF4D6D", // red-rose — threat / offline
          soft: "#FF8DA1",
          dim: "#E11D48",
        },
        violet: "#B98CFF", // purple accent (distinct categorical pop)
      },
      fontFamily: {
        display: ["var(--font-display)", "ui-sans-serif", "system-ui"],
        mono: ["var(--font-mono)", "ui-monospace", "monospace"],
        sans: ["var(--font-sans)", "ui-sans-serif", "system-ui"],
      },
      borderRadius: {
        glass: "18px",
        chip: "12px",
      },
      boxShadow: {
        "glow-signal": "0 0 0 1px rgba(159,239,0,0.24), 0 0 22px -6px rgba(159,239,0,0.45)",
        "glow-ops": "0 0 0 1px rgba(61,224,122,0.22), 0 0 22px -6px rgba(61,224,122,0.4)",
        "glow-hostile": "0 0 0 1px rgba(255,77,109,0.26), 0 0 24px -6px rgba(255,77,109,0.45)",
        glass:
          "0 10px 30px -16px rgba(0,0,0,0.7), inset 0 1px 0 0 rgba(255,255,255,0.045)",
        "card-hover":
          "0 18px 40px -20px rgba(0,0,0,0.8), inset 0 1px 0 0 rgba(255,255,255,0.06)",
      },
      keyframes: {
        "pulse-ring": {
          "0%": { transform: "scale(0.85)", opacity: "0.7" },
          "70%": { transform: "scale(1.9)", opacity: "0" },
          "100%": { transform: "scale(1.9)", opacity: "0" },
        },
        "aurora-drift": {
          "0%,100%": { transform: "translate3d(0,0,0) scale(1)" },
          "33%": { transform: "translate3d(3%,-2%,0) scale(1.06)" },
          "66%": { transform: "translate3d(-2%,3%,0) scale(0.97)" },
        },
        "grid-pan": {
          "0%": { backgroundPosition: "0 0" },
          "100%": { backgroundPosition: "44px 44px" },
        },
        scan: {
          "0%": { transform: "translateY(-120%)", opacity: "0" },
          "45%": { opacity: "0.9" },
          "100%": { transform: "translateY(120%)", opacity: "0" },
        },
        "fade-up": {
          from: { opacity: "0", transform: "translateY(8px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        blink: { "0%,100%": { opacity: "1" }, "50%": { opacity: "0.2" } },
        shimmer: {
          "0%": { backgroundPosition: "-200% 0" },
          "100%": { backgroundPosition: "200% 0" },
        },
      },
      animation: {
        "pulse-ring": "pulse-ring 2.6s cubic-bezier(0.2,0.6,0.4,1) infinite",
        "aurora-drift": "aurora-drift 26s ease-in-out infinite",
        "grid-pan": "grid-pan 40s linear infinite",
        scan: "scan 7s ease-in-out infinite",
        "fade-up": "fade-up 0.5s cubic-bezier(0.2,0.7,0.3,1) both",
        blink: "blink 1.6s steps(1) infinite",
        shimmer: "shimmer 2.4s linear infinite",
      },
    },
  },
  plugins: [],
};

export default config;
