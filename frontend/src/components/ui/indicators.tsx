import { AlertTriangle, ShieldCheck } from "lucide-react";
import { severityMeta } from "@/lib/theme";
import { cn, scoreLabel } from "@/lib/utils";
import { Badge } from "./Badge";

/** Severity pip — colored square + label (status color never alone). */
export function SeverityPip({ severity }: { severity: number }) {
  const m = severityMeta(severity);
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="h-2.5 w-2.5 rounded-[2px]" style={{ background: m.color }} />
      <span className="font-mono text-[10px] font-semibold tracking-wider" style={{ color: m.color }}>
        {m.label}
      </span>
    </span>
  );
}

/** OTX reputation badge — icon + label, never color alone. */
export function ReputationBadge({
  pulses,
  score,
}: {
  pulses: number | null | undefined;
  score?: number | null;
}) {
  if (pulses == null) return <span className="font-mono text-[11px] text-muted">unrated</span>;
  if (pulses === 0) {
    return (
      <Badge tone="ops">
        <ShieldCheck className="h-3 w-3" /> Clean
      </Badge>
    );
  }
  return (
    <Badge tone="hostile" glow>
      <AlertTriangle className="h-3 w-3" /> OTX {pulses}
      {score != null && <span className="opacity-70">· {score.toFixed(1)}</span>}
    </Badge>
  );
}

/** Coordination gauge — horizontal meter with labeled state. */
export function CoordinationGauge({ score, compact }: { score: number; compact?: boolean }) {
  const { label, color } = scoreLabel(score);
  return (
    <div className={cn("flex items-center gap-2", compact ? "min-w-[120px]" : "min-w-[160px]")}>
      <div className="relative h-1.5 flex-1 overflow-hidden rounded-full bg-white/[0.06]">
        <span
          className="absolute left-0 top-0 h-full rounded-full"
          style={{ width: `${score}%`, background: color, boxShadow: `0 0 8px ${color}` }}
        />
      </div>
      <span className="tabular w-6 text-right font-mono text-[11px] font-semibold" style={{ color }}>
        {score}
      </span>
      {!compact && (
        <span className="font-mono text-[9px] uppercase tracking-wider" style={{ color }}>
          {label}
        </span>
      )}
    </div>
  );
}
