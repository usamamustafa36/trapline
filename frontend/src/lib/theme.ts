/**
 * Chart color system — "Carbon Neon" (Hack-The-Box-inspired).
 * Categorical VPS hues are the deepened-for-dark data-mark steps; UI chrome uses
 * the brighter accents from tailwind.config.ts. Every chart that uses these ships
 * a legend or direct labels, so identity is never carried by color alone.
 * Dark chart surface: panel #111A28.
 */

// Categorical identity — assigned in FIXED order, never cycled (dataviz rule).
export const VPS_COLORS: Record<string, string> = {
  "SENSOR-01": "#57C7FF", // azure
  "SENSOR-02": "#33C88A", // jade (kept clear of the brand lime so data never reads as chrome)
  "SENSOR-03": "#FF6DA6", // rose
};

// Deployment-specific sensor artwork is intentionally not shipped. VpsLogo falls
// back to a colored initials tile, which keeps sensor identity readable without
// tying the codebase to any particular deployment.
export const VPS_LOGOS: Record<string, string> = {};
// Fixed-order categorical slots — no two share a hue, and none reuse a reserved
// status/severity color (amber/teal) so a data mark never impersonates a state.
export const CATEGORICAL = ["#57C7FF", "#33C88A", "#FF6DA6", "#B98CFF", "#5FD0FF", "#FFB0C4"];

export function vpsColor(alias: string, index = 0): string {
  return VPS_COLORS[alias] ?? CATEGORICAL[index % CATEGORICAL.length];
}

// Single-hue sequential ramp (magnitude), green dark→light.
export const SEQ_GREEN = ["#12351A", "#1E5A26", "#2C8636", "#4DB84A", "#7BDB4E", "#B6F27A"];

// Severity 0-4 status ramp (reserved status colors, always shown with a label).
export const SEVERITY = {
  0: { color: "#54AEFF", label: "INFO" },
  1: { color: "#3DE0C4", label: "LOW" },
  2: { color: "#FFC24B", label: "ELEV" },
  3: { color: "#FF9F45", label: "HIGH" },
  4: { color: "#FF4D6D", label: "CRIT" },
} as const;

export function severityMeta(sev: number) {
  return SEVERITY[(Math.max(0, Math.min(4, sev)) as 0 | 1 | 2 | 3 | 4)];
}

// Semantic status colors (bright chrome accents).
export const STATUS_COLOR: Record<string, string> = {
  online: "#3DE07A", // emerald
  stale: "#FFC24B", // amber
  offline: "#FF4D6D", // rose-red
};

export const HOSTILE = "#FF4D6D";
export const SIGNAL = "#9FEF00";
export const OPS = "#3DE07A";
export const RECON = "#54AEFF";

// Recharts shared axis/grid styling.
export const AXIS = {
  stroke: "#243449",
  tick: { fill: "#6C82A0", fontSize: 10, fontFamily: "var(--font-mono)" },
};
export const GRID_STROKE = "rgba(120,140,170,0.08)";
export const TOOLTIP_BG = "#111A28";
