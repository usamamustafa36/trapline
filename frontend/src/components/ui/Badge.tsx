import { cn } from "@/lib/utils";

type Tone = "neutral" | "signal" | "ops" | "recon" | "hostile" | "violet";

const TONES: Record<Tone, string> = {
  neutral: "border-line-bright/60 bg-white/[0.03] text-dim",
  signal: "border-signal/40 bg-signal/10 text-signal",
  ops: "border-ops/40 bg-ops/10 text-ops",
  recon: "border-recon/40 bg-recon/10 text-recon",
  hostile: "border-hostile/50 bg-hostile/10 text-hostile-soft",
  violet: "border-violet/40 bg-violet/10 text-violet",
};

export function Badge({
  children,
  tone = "neutral",
  className,
  glow,
}: {
  children: React.ReactNode;
  tone?: Tone;
  className?: string;
  glow?: boolean;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider",
        TONES[tone],
        glow && tone === "hostile" && "shadow-glow-hostile",
        className,
      )}
    >
      {children}
    </span>
  );
}
