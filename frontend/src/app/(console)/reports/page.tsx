"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import {
  ChevronLeft,
  ChevronRight,
  Download,
  FileText,
  Filter,
  Printer,
  Play,
  RotateCcw,
  Sparkles,
  CalendarRange,
  Network,
  ShieldAlert,
  Search,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import type { EventRow } from "@/lib/types";
import { cn, fmtInt, fmtTime } from "@/lib/utils";
import { EventTable } from "@/components/tables/EventTable";
import { PageHeader } from "@/components/ui/PageHeader";
import { Panel } from "@/components/ui/Panel";
import { Loader } from "@/components/ui/states";
import { VpsLogo } from "@/components/ui/VpsLogo";

interface Filters {
  vps: string;
  type: string;
  protocol: string;
  ip: string;
  min_severity: string;
  from: string;
  to: string;
}
const EMPTY: Filters = { vps: "", type: "", protocol: "", ip: "", min_severity: "", from: "", to: "" };

function toCsv(rows: EventRow[]): string {
  const cols = [
    "occurred_at", "vps_alias", "src_ip", "country_code", "protocol",
    "dst_port", "event_type", "severity", "username_tried", "password_tried", "payload_excerpt",
  ];
  const esc = (v: unknown) => {
    const s = v == null ? "" : String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const head = cols.join(",");
  const body = rows
    .map((r) => cols.map((c) => esc((r as unknown as Record<string, unknown>)[c])).join(","))
    .join("\n");
  return `${head}\n${body}`;
}

const PAGE_SIZE = 50;

const FIELD =
  "w-full rounded-xl border border-white/[0.08] bg-black/25 px-3 py-2.5 font-mono text-[12px] text-fg placeholder:text-muted transition-colors hover:border-white/[0.14] focus:border-signal/50 focus:bg-black/40 focus:outline-none [color-scheme:dark]";

export default function ReportsPage() {
  const [draft, setDraft] = useState<Filters>(EMPTY);
  const [applied, setApplied] = useState<Filters | null>(null);
  const [page, setPage] = useState(1);
  const { data: vps } = useQuery({ queryKey: ["vps"], queryFn: api.listVps });

  useEffect(() => {
    setPage(1);
  }, [applied]);

  const report = useQuery({
    queryKey: ["report", applied, page],
    enabled: !!applied,
    placeholderData: keepPreviousData,
    queryFn: () =>
      api.events({
        vps: applied!.vps || undefined,
        type: applied!.type || undefined,
        protocol: applied!.protocol || undefined,
        ip: applied!.ip || undefined,
        min_severity: applied!.min_severity || undefined,
        from: applied!.from ? new Date(applied!.from).toISOString() : undefined,
        to: applied!.to ? new Date(applied!.to).toISOString() : undefined,
        page,
        page_size: PAGE_SIZE,
      }),
  });

  const total = report.data?.total ?? 0;
  const isEstimate = report.data?.is_estimate ?? false;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  const activeChips = useMemo(() => {
    if (!applied) return [] as { key: string; label: string }[];
    const chips: { key: string; label: string }[] = [];
    if (applied.vps) chips.push({ key: "vps", label: `Sensor ${applied.vps}` });
    if (applied.protocol) chips.push({ key: "protocol", label: applied.protocol.toUpperCase() });
    if (applied.min_severity) chips.push({ key: "sev", label: `Sev ≥ ${applied.min_severity}` });
    if (applied.ip) chips.push({ key: "ip", label: applied.ip });
    if (applied.from) chips.push({ key: "from", label: `From ${applied.from.replace("T", " ")}` });
    if (applied.to) chips.push({ key: "to", label: `To ${applied.to.replace("T", " ")}` });
    return chips;
  }, [applied]);

  function download() {
    const rows = report.data?.items ?? [];
    if (!rows.length) return;
    const blob = new Blob([toCsv(rows)], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `trapline_report_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="animate-fade-up">
      <PageHeader eyebrow="Analysis · Export" title="Report Builder">
        {applied && (
          <span className="hidden items-center gap-2 rounded-full border border-white/[0.07] bg-white/[0.03] px-3 py-1.5 font-mono text-[11px] text-dim sm:inline-flex">
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-ops shadow-glow-ops" />
            Live query · {fmtTime(new Date().toISOString())}
          </span>
        )}
      </PageHeader>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        {/* ── Filter rail ─────────────────────────────────────────────── */}
        <aside className="xl:col-span-4 2xl:col-span-3">
          <div className="panel relative overflow-hidden">
            <span className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-signal/70 to-transparent opacity-80" />
            <header className="flex items-center gap-3 border-b border-white/[0.05] px-4 py-3.5">
              <span className="icon-chip h-8 w-8 border border-signal/25 bg-signal/[0.08] text-signal">
                <Filter className="h-4 w-4" />
              </span>
              <div className="min-w-0">
                <h2 className="font-display text-[13.5px] font-semibold text-fg">Query Filters</h2>
                <p className="hud-label mt-0.5">Scope the export before compile</p>
              </div>
            </header>

            <div className="flex flex-col gap-3.5 p-4">
              <Field label="Sensor" icon={<Network className="h-3 w-3" />}>
                <select
                  value={draft.vps}
                  onChange={(e) => setDraft({ ...draft, vps: e.target.value })}
                  className={FIELD}
                >
                  <option value="">All sensors</option>
                  {vps?.map((v) => (
                    <option key={v.alias} value={v.alias}>
                      {v.alias} — {v.display_name}
                    </option>
                  ))}
                </select>
                {draft.vps && (
                  <div className="mt-2 flex items-center gap-2 rounded-xl border border-white/[0.06] bg-white/[0.02] px-2.5 py-2">
                    <VpsLogo alias={draft.vps} size="sm" />
                    <span className="font-mono text-[11px] text-dim">{draft.vps}</span>
                  </div>
                )}
              </Field>

              <div className="grid grid-cols-2 gap-3">
                <Field label="Protocol">
                  <select
                    value={draft.protocol}
                    onChange={(e) => setDraft({ ...draft, protocol: e.target.value })}
                    className={FIELD}
                  >
                    {[
                      ["", "Any"],
                      ["ssh", "SSH"],
                      ["http", "HTTP"],
                      ["https", "HTTPS"],
                      ["telnet", "Telnet"],
                      ["ftp", "FTP"],
                      ["smtp", "SMTP"],
                      ["tcp", "TCP"],
                    ].map(([v, l]) => (
                      <option key={v} value={v}>
                        {l}
                      </option>
                    ))}
                  </select>
                </Field>
                <Field label="Min Severity" icon={<ShieldAlert className="h-3 w-3" />}>
                  <select
                    value={draft.min_severity}
                    onChange={(e) => setDraft({ ...draft, min_severity: e.target.value })}
                    className={FIELD}
                  >
                    {[
                      ["", "Any"],
                      ["1", "1 · Low+"],
                      ["2", "2 · Elevated+"],
                      ["3", "3 · High+"],
                      ["4", "4 · Critical"],
                    ].map(([v, l]) => (
                      <option key={v} value={v}>
                        {l}
                      </option>
                    ))}
                  </select>
                </Field>
              </div>

              <Field label="Source IP" icon={<Search className="h-3 w-3" />}>
                <input
                  type="text"
                  value={draft.ip}
                  onChange={(e) => setDraft({ ...draft, ip: e.target.value })}
                  placeholder="e.g. 185.220.101.4"
                  className={FIELD}
                />
              </Field>

              <Field label="Time Window" icon={<CalendarRange className="h-3 w-3" />}>
                <div className="grid grid-cols-1 gap-2">
                  <input
                    type="datetime-local"
                    value={draft.from}
                    onChange={(e) => setDraft({ ...draft, from: e.target.value })}
                    className={FIELD}
                    aria-label="From"
                  />
                  <input
                    type="datetime-local"
                    value={draft.to}
                    onChange={(e) => setDraft({ ...draft, to: e.target.value })}
                    className={FIELD}
                    aria-label="To"
                  />
                </div>
              </Field>

              <div className="mt-1 flex gap-2">
                <button
                  onClick={() => setApplied({ ...draft })}
                  className="inline-flex flex-1 items-center justify-center gap-2 rounded-full bg-signal px-4 py-2.5 font-mono text-[12px] font-bold uppercase tracking-wider text-void shadow-glow-signal transition-transform hover:scale-[1.01] active:scale-[0.99]"
                >
                  <Play className="h-3.5 w-3.5 fill-current" /> Compile
                </button>
                <button
                  onClick={() => {
                    setDraft(EMPTY);
                    setApplied(null);
                  }}
                  className="inline-flex items-center justify-center gap-1.5 rounded-full border border-white/[0.08] bg-white/[0.03] px-3.5 py-2.5 font-mono text-[11px] font-semibold uppercase tracking-wider text-muted transition-colors hover:border-white/[0.14] hover:text-fg"
                  title="Reset filters"
                >
                  <RotateCcw className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          </div>
        </aside>

        {/* ── Preview ─────────────────────────────────────────────────── */}
        <section className="xl:col-span-8 2xl:col-span-9">
          <Panel
            title="Report Preview"
            sub={
              applied
                ? `${isEstimate ? "~" : ""}${fmtInt(total)} matched · page ${page.toLocaleString()} / ${totalPages.toLocaleString()}`
                : "Build a query, then compile"
            }
            icon={<FileText className="h-4 w-4" />}
            bracketed
            right={
              report.data ? (
                <div className="flex items-center gap-2">
                  <button
                    onClick={download}
                    className="inline-flex items-center gap-1.5 rounded-full border border-ops/40 bg-ops/10 px-3 py-1.5 font-mono text-[11px] font-semibold uppercase tracking-wider text-ops transition-colors hover:bg-ops/20"
                  >
                    <Download className="h-3.5 w-3.5" /> CSV
                  </button>
                  <button
                    onClick={() => window.print()}
                    className="inline-flex items-center gap-1.5 rounded-full border border-white/[0.08] bg-white/[0.03] px-3 py-1.5 font-mono text-[11px] font-semibold uppercase tracking-wider text-dim transition-colors hover:text-fg"
                  >
                    <Printer className="h-3.5 w-3.5" /> PDF
                  </button>
                </div>
              ) : null
            }
          >
            {activeChips.length > 0 && (
              <div className="mb-4 flex flex-wrap items-center gap-1.5">
                <span className="hud-label mr-1">Active</span>
                {activeChips.map((c) => (
                  <span
                    key={c.key}
                    className="inline-flex items-center rounded-full border border-signal/25 bg-signal/[0.08] px-2.5 py-1 font-mono text-[10px] font-medium uppercase tracking-wider text-signal"
                  >
                    {c.label}
                  </span>
                ))}
              </div>
            )}

            {!applied ? (
              <EmptyComposer />
            ) : report.isLoading ? (
              <Loader label="Compiling report…" />
            ) : (
              <>
                {applied && (
                  <div className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-3">
                    <StatPill label="Matched" value={`${isEstimate ? "~" : ""}${fmtInt(total)}`} accent="signal" />
                    <StatPill label="This page" value={String(report.data?.items.length ?? 0)} accent="recon" />
                    <StatPill
                      label="Pages"
                      value={totalPages.toLocaleString()}
                      accent="ops"
                      className="col-span-2 sm:col-span-1"
                    />
                  </div>
                )}
                <EventTable rows={report.data?.items ?? []} />
                {total > 0 && (
                  <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-white/[0.05] pt-3.5">
                    <span className="font-mono text-[11px] text-muted">
                      Showing{" "}
                      <span className="text-dim">
                        {((page - 1) * PAGE_SIZE + 1).toLocaleString()}–
                        {Math.min(page * PAGE_SIZE, total).toLocaleString()}
                      </span>{" "}
                      of {isEstimate ? "~" : ""}
                      {fmtInt(total)}
                    </span>
                    <div className="inline-flex items-center gap-1 rounded-full border border-white/[0.07] bg-black/25 p-1">
                      <PageButton
                        disabled={page <= 1 || report.isFetching}
                        onClick={() => setPage((p) => Math.max(1, p - 1))}
                      >
                        <ChevronLeft className="h-3.5 w-3.5" /> Prev
                      </PageButton>
                      <span className="min-w-[4.5rem] px-2 text-center font-mono text-[11px] font-semibold text-fg">
                        {page.toLocaleString()} / {totalPages.toLocaleString()}
                      </span>
                      <PageButton
                        disabled={page >= totalPages || report.isFetching}
                        onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                      >
                        Next <ChevronRight className="h-3.5 w-3.5" />
                      </PageButton>
                    </div>
                  </div>
                )}
              </>
            )}
          </Panel>
        </section>
      </div>
    </div>
  );
}

function EmptyComposer() {
  return (
    <div className="relative flex min-h-[320px] flex-col items-center justify-center overflow-hidden rounded-xl border border-dashed border-white/[0.08] bg-gradient-to-b from-white/[0.02] to-transparent px-6 py-12 text-center">
      <span className="pointer-events-none absolute -top-16 left-1/2 h-40 w-40 -translate-x-1/2 rounded-full bg-signal/10 blur-3xl" />
      <span className="relative mb-4 grid h-14 w-14 place-items-center rounded-2xl border border-signal/25 bg-signal/[0.08] text-signal shadow-glow-signal">
        <Sparkles className="h-6 w-6" />
      </span>
      <h3 className="relative font-display text-[18px] font-semibold tracking-tight text-fg">
        Build your intelligence export
      </h3>
      <p className="relative mt-2 max-w-md font-mono text-[12px] leading-relaxed text-muted">
        Choose a sensor, protocol, severity, or time range on the left — then hit
        Compile to page through matching honeypot events.
      </p>
      <div className="relative mt-6 flex flex-wrap items-center justify-center gap-2">
        {["Sensor", "Protocol", "Severity", "IP", "Window"].map((step, i) => (
          <span
            key={step}
            className="inline-flex items-center gap-1.5 rounded-full border border-white/[0.07] bg-black/30 px-3 py-1 font-mono text-[10px] uppercase tracking-wider text-dim"
            style={{ animationDelay: `${i * 80}ms` }}
          >
            <span className="text-signal/80">{String(i + 1).padStart(2, "0")}</span>
            {step}
          </span>
        ))}
      </div>
    </div>
  );
}

function Field({
  label,
  icon,
  children,
}: {
  label: string;
  icon?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div>
      <label className="mb-1.5 flex items-center gap-1.5">
        {icon && <span className="text-muted">{icon}</span>}
        <span className="hud-label !text-[9px]">{label}</span>
      </label>
      {children}
    </div>
  );
}

function StatPill({
  label,
  value,
  accent,
  className,
}: {
  label: string;
  value: string;
  accent: "signal" | "ops" | "recon";
  className?: string;
}) {
  const tone = {
    signal: "border-signal/20 bg-signal/[0.06] text-signal",
    ops: "border-ops/20 bg-ops/[0.06] text-ops",
    recon: "border-recon/20 bg-recon/[0.06] text-recon",
  }[accent];
  return (
    <div className={cn("rounded-xl border px-3.5 py-2.5", tone, className)}>
      <div className="hud-label !text-[8.5px] opacity-80">{label}</div>
      <div className="mt-1 font-display text-[20px] font-bold tabular leading-none">{value}</div>
    </div>
  );
}

function PageButton({
  children,
  disabled,
  onClick,
}: {
  children: React.ReactNode;
  disabled?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className="inline-flex items-center gap-1 rounded-full px-3 py-1.5 font-mono text-[11px] font-semibold uppercase tracking-wider text-dim transition-colors hover:bg-white/[0.06] hover:text-fg disabled:cursor-not-allowed disabled:opacity-35 disabled:hover:bg-transparent disabled:hover:text-dim"
    >
      {children}
    </button>
  );
}
