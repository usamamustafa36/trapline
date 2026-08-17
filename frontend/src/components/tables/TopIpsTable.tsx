import Link from "next/link";
import { vpsColor } from "@/lib/theme";
import type { CrossVpsIp } from "@/lib/types";
import { flag, fmtInt, relTime, shortAlias } from "@/lib/utils";
import { Badge } from "@/components/ui/Badge";
import { CoordinationGauge, ReputationBadge } from "@/components/ui/indicators";
import { Empty } from "@/components/ui/states";

export function TopIpsTable({
  rows,
  showCoordination = true,
}: {
  rows: CrossVpsIp[];
  showCoordination?: boolean;
}) {
  if (!rows.length) return <Empty />;
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-left">
        <thead>
          <tr className="border-b border-line text-muted">
            <th className="th">Source IP</th>
            <th className="th">Sensors</th>
            <th className="th text-right">Events</th>
            <th className="th">Reputation</th>
            {showCoordination && <th className="th">Coordination</th>}
            <th className="th">Last Seen</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((ip) => (
            <tr key={ip.ip} className="group border-b border-line/50 transition-colors hover:bg-white/[0.025]">
              <td className="td">
                <Link
                  href={`/ips/${encodeURIComponent(ip.ip)}`}
                  className="inline-flex items-center gap-2 font-mono text-[12px] text-fg transition-colors hover:text-signal"
                >
                  <span>{flag(ip.country_code)}</span>
                  <span className="group-hover:underline">{ip.ip}</span>
                  {ip.vps_count > 1 && (
                    <Badge tone="hostile" className="!py-0">
                      ×{ip.vps_count}
                    </Badge>
                  )}
                </Link>
              </td>
              <td className="td">
                <div className="flex items-center gap-1">
                  {ip.vps_aliases.map((a) => (
                    <span
                      key={a}
                      className="grid h-4 min-w-[22px] place-items-center rounded-[3px] px-1 font-mono text-[9px] font-bold leading-none text-void"
                      style={{ background: vpsColor(a) }}
                      title={a}
                    >
                      {shortAlias(a)}
                    </span>
                  ))}
                </div>
              </td>
              <td className="td tabular text-right font-mono text-[12px] font-semibold text-fg">
                {fmtInt(ip.total_events)}
              </td>
              <td className="td">
                <ReputationBadge pulses={ip.otx_pulse_count} score={ip.reputation_score} />
              </td>
              {showCoordination && (
                <td className="td">
                  <CoordinationGauge score={ip.coordination_score} compact />
                </td>
              )}
              <td className="td whitespace-nowrap font-mono text-[11px] text-muted">
                {relTime(ip.last_seen_at)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
