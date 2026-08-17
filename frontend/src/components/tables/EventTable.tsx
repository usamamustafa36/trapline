import Link from "next/link";
import { vpsColor } from "@/lib/theme";
import type { EventRow } from "@/lib/types";
import { flag, fmtTime, relTime } from "@/lib/utils";
import { SeverityPip } from "@/components/ui/indicators";
import { Empty } from "@/components/ui/states";

export function EventTable({
  rows,
  compact = false,
  showVps = true,
}: {
  rows: EventRow[];
  compact?: boolean;
  showVps?: boolean;
}) {
  if (!rows.length) return <Empty />;
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-left">
        <thead>
          <tr className="border-b border-line text-muted">
            <th className="th">Sev</th>
            <th className="th">Time</th>
            {showVps && <th className="th">Sensor</th>}
            <th className="th">Source IP</th>
            <th className="th">Proto</th>
            <th className="th">Port</th>
            {!compact && <th className="th">User</th>}
            {!compact && <th className="th">Secret</th>}
            <th className="th">Vector</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((e) => (
            <tr
              key={e.id}
              className="group border-b border-line/50 transition-colors hover:bg-white/[0.025]"
            >
              <td className="td">
                <SeverityPip severity={e.severity} />
              </td>
              <td className="td whitespace-nowrap font-mono text-[11px] text-dim">
                <span className="text-fg">{relTime(e.occurred_at)}</span>
                <span className="ml-1.5 hidden text-muted xl:inline">{fmtTime(e.occurred_at)}</span>
              </td>
              {showVps && (
                <td className="td">
                  <span className="inline-flex items-center gap-1.5">
                    <span
                      className="h-2 w-2 rounded-[2px]"
                      style={{ background: vpsColor(e.vps_alias ?? "") }}
                    />
                    <span className="font-mono text-[11px] font-semibold text-dim">{e.vps_alias}</span>
                  </span>
                </td>
              )}
              <td className="td">
                <Link
                  href={`/ips/${encodeURIComponent(e.src_ip)}`}
                  className="inline-flex items-center gap-1.5 font-mono text-[12px] text-recon transition-colors hover:text-recon-soft hover:underline"
                >
                  <span>{flag(e.country_code)}</span>
                  {e.src_ip}
                </Link>
              </td>
              <td className="td font-mono text-[11px] uppercase text-dim">{e.protocol ?? "—"}</td>
              <td className="td tabular font-mono text-[11px] text-muted">{e.dst_port ?? "—"}</td>
              {!compact && (
                <td className="td max-w-[110px] truncate font-mono text-[11px] text-dim">
                  {e.username_tried ?? "—"}
                </td>
              )}
              {!compact && (
                <td className="td max-w-[120px] truncate font-mono text-[11px] text-signal/80">
                  {e.password_tried ?? "—"}
                </td>
              )}
              <td className="td max-w-[220px] truncate font-mono text-[11px] text-muted" title={e.payload_excerpt ?? e.event_type ?? ""}>
                {e.payload_excerpt ?? e.event_type ?? "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
