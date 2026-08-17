"use client";

/**
 * Generated detection content.
 *
 * The point of this page: honeypot telemetry leaves here as artefacts a defence
 * stack consumes, not as a chart. Sigma rules for a SIEM, a scored blocklist, and a
 * STIX bundle for a threat-intel platform.
 *
 * Every rule shows what it was derived from, so a reader can tell a signature backed
 * by 58 addresses from a coincidence backed by 3.
 */
import { useQuery } from "@tanstack/react-query";
import { ShieldAlert, Ban, Share2, Download, ChevronRight } from "lucide-react";
import { useState } from "react";
import { api } from "@/lib/api";
import { fmtInt } from "@/lib/utils";
import { KpiTile } from "@/components/ui/KpiTile";
import { PageHeader } from "@/components/ui/PageHeader";
import { Panel } from "@/components/ui/Panel";
import { ErrorState, Loader } from "@/components/ui/states";
import { cn } from "@/lib/utils";

const LEVEL: Record<string, string> = {
  critical: "border-alert/40 bg-alert/15 text-alert",
  high: "border-warn/40 bg-warn/15 text-warn",
  medium: "border-signal/30 bg-signal/10 text-signal",
  low: "border-white/12 bg-white/[0.04] text-dim",
};

function evidenceLine(ev: Record<string, unknown>): string {
  const parts: string[] = [];
  if (typeof ev.source_addresses === "number") parts.push(`${fmtInt(ev.source_addresses)} addresses`);
  if (typeof ev.events === "number") parts.push(`${fmtInt(ev.events)} events`);
  if (typeof ev.http_events === "number") parts.push(`${fmtInt(ev.http_events)} HTTP events`);
  if (typeof ev.multi_sensor_addresses === "number")
    parts.push(`${fmtInt(ev.multi_sensor_addresses)} multi-sensor addresses`);
  if (typeof ev.ladder_length === "number") parts.push(`${ev.ladder_length}-step ladder`);
  return parts.join(" · ") || "derived from observed telemetry";
}

export default function DetectionsPage() {
  const [open, setOpen] = useState<string | null>(null);
  const rules = useQuery({ queryKey: ["sigma"], queryFn: api.sigmaRules });
  const bl = useQuery({ queryKey: ["blocklist"], queryFn: api.blocklist });

  if (rules.isLoading) return <Loader label="deriving detection content…" />;
  if (rules.isError || !rules.data)
    return <ErrorState message={String(rules.error ?? "rule generation failed")} />;

  const counts = rules.data.rules.reduce<Record<string, number>>((acc, r) => {
    acc[r.level] = (acc[r.level] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <div className="flex flex-col gap-5">
      <PageHeader eyebrow="Defence · Generated content" title="Detections" />

      <Panel
        title="What this is"
        icon={<ShieldAlert className="h-4 w-4" />}
        sub="Rules and indicators derived from what the sensors actually observed. Trapline is not a SIEM: it produces detection content for one"
      >
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <KpiTile label="Sigma rules" value={fmtInt(rules.data.count)} sub="deployable" />
          <KpiTile
            label="Critical / high"
            value={fmtInt((counts.critical ?? 0) + (counts.high ?? 0))}
            sub="by severity"
          />
          <KpiTile
            label="Blocklist"
            value={bl.data ? fmtInt(bl.data.total) : "…"}
            sub={bl.data ? `${bl.data.high_confidence} high confidence` : undefined}
          />
          <KpiTile label="Formats" value="3" sub="Sigma · STIX · nftables" />
        </div>
        <div className="mt-4 flex flex-wrap gap-2">
          <a
            href={api.sigmaYamlUrl()}
            className="flex items-center gap-2 rounded-lg border border-signal/30 bg-signal/10 px-3 py-2 font-mono text-[12px] text-signal transition-colors hover:bg-signal/20"
          >
            <Download className="h-3.5 w-3.5" /> trapline-sigma.yml
          </a>
          <a
            href={`${api.base}/detections/stix`}
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-2 rounded-lg border border-white/12 bg-white/[0.04] px-3 py-2 font-mono text-[12px] text-dim transition-colors hover:bg-white/[0.08]"
          >
            <Share2 className="h-3.5 w-3.5" /> STIX 2.1 bundle
          </a>
          <a
            href={`${api.base}/detections/blocklist`}
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-2 rounded-lg border border-white/12 bg-white/[0.04] px-3 py-2 font-mono text-[12px] text-dim transition-colors hover:bg-white/[0.08]"
          >
            <Ban className="h-3.5 w-3.5" /> blocklist
          </a>
        </div>
      </Panel>

      <Panel
        title="Sigma rules"
        icon={<ShieldAlert className="h-4 w-4" />}
        sub="Vendor-neutral detection rules. Click one to see its logic and the evidence it rests on"
      >
        <div className="flex flex-col gap-2">
          {rules.data.rules.map((r) => {
            const isOpen = open === r.id;
            return (
              <div
                key={r.id}
                className="overflow-hidden rounded-xl border border-white/[0.06] bg-black/20"
              >
                <button
                  onClick={() => setOpen(isOpen ? null : r.id)}
                  className="flex w-full items-center gap-3 px-3 py-2.5 text-left transition-colors hover:bg-white/[0.03]"
                >
                  <ChevronRight
                    className={cn(
                      "h-3.5 w-3.5 shrink-0 text-muted transition-transform",
                      isOpen && "rotate-90",
                    )}
                  />
                  <span
                    className={cn(
                      "shrink-0 rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase",
                      LEVEL[r.level] ?? LEVEL.low,
                    )}
                  >
                    {r.level}
                  </span>
                  <span className="min-w-0 flex-1 truncate text-[13px] text-fg">{r.title}</span>
                  <span className="hidden shrink-0 font-mono text-[10.5px] text-muted sm:inline">
                    {evidenceLine(r.trapline_evidence)}
                  </span>
                </button>
                {isOpen && (
                  <div className="border-t border-white/[0.06] px-3 py-3">
                    <p className="text-[12.5px] leading-relaxed text-dim">{r.description}</p>
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {r.tags.map((t) => (
                        <a
                          key={t}
                          href={
                            t.startsWith("attack.t")
                              ? `https://attack.mitre.org/techniques/${t
                                  .replace("attack.", "")
                                  .toUpperCase()
                                  .replace(".", "/")}/`
                              : "https://attack.mitre.org/"
                          }
                          target="_blank"
                          rel="noreferrer"
                          className="rounded border border-signal/25 bg-signal/[0.08] px-1.5 py-0.5 font-mono text-[10px] text-signal hover:bg-signal/20"
                        >
                          {t}
                        </a>
                      ))}
                    </div>
                    <div className="mt-3 grid gap-3 lg:grid-cols-2">
                      <div>
                        <div className="hud-label mb-1">Detection</div>
                        <pre className="max-h-52 overflow-auto whitespace-pre-wrap break-all rounded bg-black/40 p-2 font-mono text-[10.5px] leading-relaxed text-muted">
                          {JSON.stringify(r.detection, null, 1)}
                        </pre>
                      </div>
                      <div>
                        <div className="hud-label mb-1">Evidence</div>
                        <pre className="max-h-52 overflow-auto whitespace-pre-wrap break-all rounded bg-black/40 p-2 font-mono text-[10.5px] leading-relaxed text-muted">
                          {JSON.stringify(r.trapline_evidence, null, 1)}
                        </pre>
                      </div>
                    </div>
                    {r.falsepositives?.length > 0 && (
                      <div className="mt-2 font-mono text-[11px] text-warn">
                        False positives: {r.falsepositives.join("; ")}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </Panel>

      {bl.data && (
        <Panel
          title="Blocklist"
          icon={<Ban className="h-4 w-4" />}
          sub="Confidence comes from cross-sensor timing, not reputation. Whether blocking these actually reduces return traffic is measurable and not yet measured"
        >
          <div className="overflow-x-auto">
            <table className="w-full min-w-[480px] text-left font-mono text-[12px]">
              <thead className="text-muted">
                <tr className="border-b border-white/[0.06]">
                  <th className="pb-2 pr-3 font-normal">Address</th>
                  <th className="pb-2 pr-3 font-normal">Confidence</th>
                  <th className="pb-2 pr-3 font-normal">Reason</th>
                  <th className="pb-2 text-right font-normal">Events</th>
                </tr>
              </thead>
              <tbody>
                {bl.data.entries.slice(0, 16).map((e) => (
                  <tr key={e.ip} className="border-b border-white/[0.03]">
                    <td className="py-2 pr-3 text-fg">{e.ip}</td>
                    <td className="py-2 pr-3">
                      <span
                        className={cn(
                          "rounded border px-1.5 py-0.5 text-[10px]",
                          e.confidence >= 0.9 ? LEVEL.critical : LEVEL.medium,
                        )}
                      >
                        {e.confidence.toFixed(2)}
                      </span>
                    </td>
                    <td className="py-2 pr-3 text-dim">{e.reason}</td>
                    <td className="py-2 text-right text-signal">{fmtInt(e.events)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mt-3">
            <div className="hud-label mb-1">nftables set (high confidence only)</div>
            <pre className="max-h-40 overflow-auto rounded bg-black/40 p-2 font-mono text-[10.5px] leading-relaxed text-muted">
              {bl.data.nftables}
            </pre>
          </div>
          <p className="mt-2 text-[11.5px] leading-relaxed text-warn">{bl.data.note}</p>
        </Panel>
      )}
    </div>
  );
}
