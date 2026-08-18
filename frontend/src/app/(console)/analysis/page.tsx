"use client";

/**
 * Attribution analysis.
 *
 * Every panel answers a question the event feed cannot, and every number is shown
 * with the evidence it rests on: how many source addresses, how many events, and
 * example rows. Nothing here is a bare score.
 */
import { useQuery } from "@tanstack/react-query";
import {
  Fingerprint,
  GitBranch,
  KeyRound,
  Terminal,
  Clock,
  Globe,
  Users,
} from "lucide-react";
import { api } from "@/lib/api";
import { fmtInt } from "@/lib/utils";
import { KpiTile } from "@/components/ui/KpiTile";
import { PageHeader } from "@/components/ui/PageHeader";
import { Panel } from "@/components/ui/Panel";
import { ErrorState, Loader } from "@/components/ui/states";
import { cn } from "@/lib/utils";

const VERDICT_STYLE: Record<string, string> = {
  "sequential sweep": "text-alert border-alert/30 bg-alert/10",
  "parallel (distributed)": "text-alert border-alert/30 bg-alert/10",
  "recurring visitor": "text-warn border-warn/30 bg-warn/10",
  "background scanning": "text-muted border-white/10 bg-white/[0.04]",
};

const LEVEL_ORDER = ["Profile host", "Escalate", "Prepare host", "Fetch payload", "Install", "Persist", "Evade", "Clean up", "Act"];

function secs(n: number): string {
  if (n < 90) return `${n}s`;
  if (n < 5400) return `${Math.round(n / 60)}m`;
  if (n < 172800) return `${(n / 3600).toFixed(1)}h`;
  return `${Math.round(n / 86400)}d`;
}

export default function AnalysisPage() {
  const q = useQuery({ queryKey: ["analysisReport"], queryFn: api.analysisReport });

  if (q.isLoading) return <Loader label="running analysis over the full event set…" />;
  if (q.isError || !q.data) return <ErrorState message={String(q.error ?? "analysis failed")} />;

  const r = q.data;
  const human = r.clients.buckets["interactive (likely human)"];
  const sweeps =
    (r.coordination.verdicts["sequential sweep"] ?? 0) +
    (r.coordination.verdicts["parallel (distributed)"] ?? 0);
  const maxHour = Math.max(...r.rhythm.by_hour_utc, 1);
  const phases = [...r.commands.phases].sort(
    (a, b) => LEVEL_ORDER.indexOf(a.label) - LEVEL_ORDER.indexOf(b.label),
  );

  return (
    <div className="flex flex-col gap-5">
      <PageHeader eyebrow="Intelligence · Attribution" title="Attribution Analysis" />

      {/* Deployment reality, stated up front so nothing is overclaimed. */}
      <Panel title="Deployment" icon={<Globe className="h-4 w-4" />}>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {r.overview.sensors.map((s) => (
            <div
              key={s.alias}
              className="rounded-xl border border-white/[0.06] bg-black/20 p-3"
            >
              <div className="font-mono text-[13px] font-semibold text-fg">{s.alias}</div>
              <div className="mt-1 font-mono text-[11px] text-muted">
                {s.first.slice(0, 10)} → {s.last.slice(0, 10)} · {s.days} days
              </div>
              <div className="mt-2 flex gap-4 font-mono text-[12px]">
                <span className="text-signal">{fmtInt(s.events)} events</span>
                <span className="text-dim">{fmtInt(s.addresses)} addresses</span>
              </div>
            </div>
          ))}
        </div>
      </Panel>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <KpiTile label="Events" value={fmtInt(r.overview.events)} />
        <KpiTile label="Source addresses" value={fmtInt(r.overview.addresses)} />
        <KpiTile
          label="Multi-sensor addresses"
          value={fmtInt(r.coordination.multi_sensor_addresses)}
          sub={`${sweeps} coordinated`}
        />
        <KpiTile
          label="Interactive clients"
          value={human ? `${human.share}%` : "—"}
          sub={human ? `${fmtInt(human.addresses)} addresses` : undefined}
        />
      </div>

      {/* Cross-sensor coordination: the lag shape, not just the flag. */}
      <Panel
        title="Cross-sensor coordination"
        icon={<GitBranch className="h-4 w-4" />}
        sub="An address on several sensors is classified by the shape of its inter-sensor lag: an ordered walk is one scanner sweeping, near-simultaneous arrivals are distributed, weeks apart is background noise"
      >
        <div className="mb-4 flex flex-wrap gap-2">
          {Object.entries(r.coordination.verdicts)
            .sort((a, b) => b[1] - a[1])
            .map(([verdict, n]) => (
              <span
                key={verdict}
                className={cn(
                  "rounded-lg border px-2.5 py-1 font-mono text-[11px]",
                  VERDICT_STYLE[verdict] ?? "border-white/10 bg-white/[0.04] text-dim",
                )}
              >
                {verdict} · {fmtInt(n)}
              </span>
            ))}
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[560px] text-left font-mono text-[12px]">
            <thead className="text-muted">
              <tr className="border-b border-white/[0.06]">
                <th className="pb-2 pr-3 font-normal">Address</th>
                <th className="pb-2 pr-3 font-normal">Verdict</th>
                <th className="pb-2 pr-3 font-normal">Order</th>
                <th className="pb-2 pr-3 text-right font-normal">Max lag</th>
                <th className="pb-2 text-right font-normal">Events</th>
              </tr>
            </thead>
            <tbody>
              {r.coordination.addresses.slice(0, 14).map((a) => (
                <tr key={a.ip} className="border-b border-white/[0.03]">
                  <td className="py-2 pr-3 text-fg">{a.ip}</td>
                  <td className="py-2 pr-3">
                    <span
                      className={cn(
                        "rounded border px-1.5 py-0.5 text-[10px]",
                        VERDICT_STYLE[a.verdict] ?? "border-white/10 text-dim",
                      )}
                    >
                      {a.verdict}
                    </span>
                  </td>
                  <td className="py-2 pr-3 text-dim">{a.order.join(" → ")}</td>
                  <td className="py-2 pr-3 text-right text-dim">{secs(a.max_lag_seconds)}</td>
                  <td className="py-2 text-right text-signal">{fmtInt(a.events)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        {/* Client fingerprints: the human-presence signal. */}
        <Panel
          title="Client fingerprints"
          icon={<Users className="h-4 w-4" />}
          sub="SSH version strings are tool fingerprints. Interactive GUI clients mean a human at a keyboard; libraries mean a script"
        >
          <div className="mb-3 flex flex-col gap-2">
            {Object.entries(r.clients.buckets)
              .sort((a, b) => b[1].events - a[1].events)
              .map(([name, b]) => (
                <div key={name}>
                  <div className="flex items-baseline justify-between gap-2 font-mono text-[12px]">
                    <span
                      className={cn(
                        "min-w-0 truncate",
                        name.startsWith("interactive") ? "text-alert" : "text-dim",
                      )}
                      title={name}
                    >
                      {name}
                    </span>
                    <span className="shrink-0 text-muted">
                      {b.share}% · {fmtInt(b.addresses)} addrs
                    </span>
                  </div>
                  <div className="mt-1 h-1.5 overflow-hidden rounded bg-white/[0.05]">
                    <div
                      className={cn(
                        "h-full rounded",
                        name.startsWith("interactive") ? "bg-alert" : "bg-signal/60",
                      )}
                      style={{ width: `${Math.max(b.share, 0.6)}%` }}
                    />
                  </div>
                </div>
              ))}
          </div>
          <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-[11.5px]">
            <tbody>
              {r.clients.clients.slice(0, 9).map((c) => (
                <tr key={c.client} className="border-b border-white/[0.03]">
                  <td className="max-w-[220px] break-all py-1.5 pr-2 text-fg">
                    {c.client.replace("SSH-2.0-", "")}
                  </td>
                  <td className="py-1.5 pr-2 text-right text-signal">{fmtInt(c.events)}</td>
                  <td className="py-1.5 text-[10px] text-muted">
                    {c.bucket.startsWith("interactive") ? "human" : c.bucket.startsWith("automation") ? "script" : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        </Panel>

        {/* Credential ladders: tool attribution from wordlist order. */}
        <Panel
          title="Credential ladders"
          icon={<KeyRound className="h-4 w-4" />}
          sub="The same wordlist in the same order from many addresses means the same software"
        >
          <div className="mb-3 flex gap-4 font-mono text-[12px]">
            <span className="text-dim">
              {fmtInt(r.credentials.sources_with_ladders)} sources
            </span>
            <span className="text-signal">
              {fmtInt(r.credentials.shared_ladder_groups)} shared groups
            </span>
          </div>
          <div className="flex flex-col gap-2">
            {r.credentials.groups.slice(0, 6).map((g, i) => (
              <div
                key={i}
                className="rounded-lg border border-white/[0.06] bg-black/20 p-2.5"
              >
                <div className="flex items-baseline justify-between">
                  <span className="font-mono text-[12px] text-alert">
                    {g.address_count} addresses
                  </span>
                  <span className="font-mono text-[10px] text-muted">
                    {g.ladder_length}-step ladder
                  </span>
                </div>
                <div className="mt-1.5 truncate font-mono text-[11px] text-dim">
                  {g.ladder.slice(0, 5).join(" → ")}
                </div>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      {/* Command lifecycle with ATT&CK. */}
      <Panel
        title="Post-compromise command lifecycle"
        icon={<Terminal className="h-4 w-4" />}
        sub={`${fmtInt(r.commands.classified)} of ${fmtInt(r.commands.total_command_events)} command events classified, mapped to MITRE ATT&CK`}
      >
        <div className="flex flex-col gap-2.5">
          {phases.map((p) => (
            <div
              key={p.label}
              className="rounded-xl border border-white/[0.06] bg-black/20 p-3"
            >
              <div className="flex flex-wrap items-baseline gap-2">
                <span className="font-mono text-[13px] font-semibold text-fg">{p.label}</span>
                {p.attck && (
                  <a
                    href={`https://attack.mitre.org/techniques/${p.attck.replace(".", "/")}/`}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex min-h-[24px] items-center rounded border border-signal/30 bg-signal/10 px-2 py-0.5 font-mono text-[10px] text-signal transition-colors hover:bg-signal/20"
                  >
                    {p.attck}
                  </a>
                )}
                <span className="text-[12px] text-dim">{p.detail}</span>
                <span className="ml-auto font-mono text-[11px] text-muted">
                  {fmtInt(p.count)} events · {p.sources} sources
                </span>
              </div>
              {p.evidence.length > 0 && (
                <pre className="mt-2 max-h-24 overflow-y-auto whitespace-pre-wrap break-all rounded bg-black/40 p-2 font-mono text-[10.5px] leading-relaxed text-muted">
                  {p.evidence.slice(0, 3).join("\n")}
                </pre>
              )}
            </div>
          ))}
        </div>
      </Panel>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        {/* Rhythm. */}
        <Panel title="Activity rhythm (UTC)" icon={<Clock className="h-4 w-4" />} sub={r.rhythm.reading}>
          <div className="flex h-28 items-end gap-[3px]">
            {r.rhythm.by_hour_utc.map((c, h) => (
              // h-full and flex-end so the child's percentage height has a box to
              // resolve against; without it every bar collapses to zero.
              <div key={h} className="group relative flex h-full flex-1 items-end">
                <div
                  className={cn(
                    "w-full rounded-t",
                    h === r.rhythm.peak_hour_utc
                      ? "bg-alert"
                      : h === r.rhythm.trough_hour_utc
                        ? "bg-ops"
                        : "bg-signal/50",
                  )}
                  style={{ height: `${Math.max((c / maxHour) * 100, 2)}%` }}
                  title={`${String(h).padStart(2, "0")}:00 — ${fmtInt(c)} events`}
                />
              </div>
            ))}
          </div>
          <div className="mt-2 flex justify-between font-mono text-[10px] text-muted">
            <span>00</span><span>06</span><span>12</span><span>18</span><span>23</span>
          </div>
          <div className="mt-2 font-mono text-[11px] text-dim">
            cv {r.rhythm.coefficient_of_variation} · peak{" "}
            {String(r.rhythm.peak_hour_utc).padStart(2, "0")}:00 · trough{" "}
            {String(r.rhythm.trough_hour_utc).padStart(2, "0")}:00
          </div>
        </Panel>

        {/* Credential attack style, a real ATT&CK sub-technique split. */}
        <Panel
          title="Credential attack style"
          icon={<KeyRound className="h-4 w-4" />}
          sub="Separated by account-to-password fan-out, which is what distinguishes the T1110 sub-techniques"
        >
          <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-[12px]">
            <tbody>
              {Object.entries(r.guessing.styles)
                .sort((a, b) => b[1] - a[1])
                .map(([style, n]) => (
                  <tr key={style} className="border-b border-white/[0.03]">
                    <td className="py-2 text-dim">{style}</td>
                    <td className="py-2 text-right text-signal">{fmtInt(n)} sources</td>
                  </tr>
                ))}
            </tbody>
          </table>
          </div>
          <div className="mt-3 hud-label">Most requested HTTP paths</div>
          <div className="overflow-x-auto">
          <table className="mt-1 w-full text-left font-mono text-[11.5px]">
            <tbody>
              {r.http.top_paths.slice(0, 6).map((p) => (
                <tr key={p.uri} className="border-b border-white/[0.03]">
                  <td className="max-w-[240px] truncate py-1.5 pr-2 text-fg" title={p.uri}>
                    {p.uri}
                  </td>
                  <td className="py-1.5 text-right text-signal">{fmtInt(p.count)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        </Panel>
      </div>
    </div>
  );
}
