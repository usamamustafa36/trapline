import { cn } from "@/lib/utils";

type Accent = "signal" | "ops" | "recon" | "hostile" | "violet";

const ACCENT: Record<
  Accent,
  { text: string; textGlow: string; chip: string; line: string; wash: string }
> = {
  signal: {
    text: "text-signal",
    textGlow: "text-glow-signal",
    chip: "border-signal/25 bg-signal/[0.08] text-signal",
    line: "from-signal/70",
    wash: "rgba(159,239,0,0.10)",
  },
  ops: {
    text: "text-ops",
    textGlow: "text-glow-ops",
    chip: "border-ops/25 bg-ops/[0.08] text-ops",
    line: "from-ops/70",
    wash: "rgba(61,224,122,0.10)",
  },
  recon: {
    text: "text-recon",
    textGlow: "text-glow-recon",
    chip: "border-recon/25 bg-recon/[0.08] text-recon",
    line: "from-recon/70",
    wash: "rgba(84,174,255,0.10)",
  },
  hostile: {
    text: "text-hostile-soft",
    textGlow: "text-glow-hostile",
    chip: "border-hostile/25 bg-hostile/[0.08] text-hostile-soft",
    line: "from-hostile/70",
    wash: "rgba(255,77,109,0.10)",
  },
  violet: {
    text: "text-violet",
    textGlow: "text-glow-violet",
    chip: "border-violet/25 bg-violet/[0.08] text-violet",
    line: "from-violet/70",
    wash: "rgba(185,140,255,0.10)",
  },
};

export function KpiTile({
  label,
  value,
  sub,
  accent = "signal",
  icon,
  footer,
}: {
  label: string;
  value: React.ReactNode;
  sub?: string;
  accent?: Accent;
  icon?: React.ReactNode;
  footer?: React.ReactNode;
}) {
  const a = ACCENT[accent];
  return (
    <div className="panel group relative overflow-hidden p-4 hover:-translate-y-0.5 hover:border-white/[0.1] hover:shadow-card-hover">
      {/* top accent line */}
      <span
        className={cn(
          "pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r to-transparent opacity-70",
          a.line,
        )}
      />
      {/* soft accent wash, brightens on hover */}
      <span
        className="pointer-events-none absolute -right-8 -top-10 h-24 w-24 rounded-full opacity-50 blur-2xl transition-opacity duration-300 group-hover:opacity-90"
        style={{ background: a.wash }}
      />
      <div className="relative flex items-center gap-2.5">
        {icon && (
          <span className={cn("icon-chip h-8 w-8 border", a.chip)}>{icon}</span>
        )}
        <span className="hud-label">{label}</span>
      </div>
      <div
        className={cn(
          "relative mt-3 font-display text-[32px] font-bold leading-none tabular",
          a.text,
          a.textGlow,
        )}
      >
        {value}
      </div>
      {sub && <div className="relative mt-2 font-mono text-[11px] text-dim">{sub}</div>}
      {footer && <div className="relative mt-2">{footer}</div>}
    </div>
  );
}
