import Link from "next/link";
import { STATUS_COLOR, vpsColor } from "@/lib/theme";
import type { Vps } from "@/lib/types";
import { fmtInt, relTime } from "@/lib/utils";
import { StatusDot } from "@/components/ui/StatusDot";
import { VpsLogo } from "@/components/ui/VpsLogo";

export function VpsHealthStrip({ sensors }: { sensors: Vps[] }) {
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
      {sensors.map((v) => (
        <Link
          key={v.id}
          href={`/vps/${v.alias}`}
          className="panel group relative flex items-center gap-3 overflow-hidden p-3.5 hover:-translate-y-0.5 hover:border-white/[0.1] hover:shadow-card-hover"
        >
          <span
            className="pointer-events-none absolute inset-x-0 top-0 h-px opacity-70"
            style={{ background: `linear-gradient(90deg, ${vpsColor(v.alias)}, transparent 70%)` }}
          />
          <VpsLogo alias={v.alias} size="md" />
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <span className="truncate font-display text-[13px] font-semibold text-fg">
                {v.display_name}
              </span>
            </div>
            <div className="mt-1.5 flex items-baseline gap-2">
              <span className="tabular font-display text-[20px] font-bold leading-none text-signal text-glow-signal">
                {fmtInt(v.event_count)}
              </span>
              <span className="font-mono text-[11px] uppercase tracking-wider text-dim">evt</span>
              {v.region && (
                <span className="truncate font-mono text-[10px] text-muted">· {v.region}</span>
              )}
            </div>
          </div>
          <div className="flex flex-col items-end gap-1.5">
            <span
              className="inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5"
              style={{
                borderColor: `${STATUS_COLOR[v.status]}44`,
                background: `${STATUS_COLOR[v.status]}14`,
              }}
            >
              <StatusDot status={v.status} />
              <span
                className="font-mono text-[10px] font-semibold uppercase tracking-wider"
                style={{ color: STATUS_COLOR[v.status] }}
              >
                {v.status}
              </span>
            </span>
            <span className="font-mono text-[9px] text-muted">{relTime(v.last_seen_at)}</span>
          </div>
        </Link>
      ))}
    </div>
  );
}
