"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Cpu, KeyRound, Plus, ShieldCheck, Copy, Check, Terminal } from "lucide-react";
import { useState } from "react";
import { api } from "@/lib/api";
import { STATUS_COLOR, vpsColor } from "@/lib/theme";
import { fmtInt, relTime } from "@/lib/utils";
import { Badge } from "@/components/ui/Badge";
import { PageHeader } from "@/components/ui/PageHeader";
import { Panel } from "@/components/ui/Panel";
import { StatusDot } from "@/components/ui/StatusDot";
import { VpsLogo } from "@/components/ui/VpsLogo";
import { Loader } from "@/components/ui/states";

export default function SettingsVpsPage() {
  const qc = useQueryClient();
  const vps = useQuery({ queryKey: ["vps"], queryFn: api.listVps, refetchInterval: 15_000 });

  const [form, setForm] = useState({
    alias: "",
    display_name: "",
    base_url: "",
    stack_type: "html_fastapi",
    region: "",
  });
  const [admin, setAdmin] = useState("");
  const [issued, setIssued] = useState<{ alias: string; api_key: string } | null>(null);
  const [copied, setCopied] = useState(false);

  const register = useMutation({
    mutationFn: () => api.registerVps(form, admin),
    onSuccess: (res) => {
      setIssued({ alias: res.alias, api_key: res.api_key });
      setForm({ alias: "", display_name: "", base_url: "", stack_type: "html_fastapi", region: "" });
      qc.invalidateQueries({ queryKey: ["vps"] });
    },
  });

  function copyKey() {
    if (!issued) return;
    navigator.clipboard.writeText(issued.api_key);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <div className="animate-fade-up">
      <PageHeader eyebrow="Configuration · Sensor Grid" title="Sensor Management" />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        {/* Registered sensors */}
        <div className="xl:col-span-2">
          <Panel title="Registered Sensors" sub="Honeypot source nodes" icon={<Cpu className="h-4 w-4" />}>
            {vps.isLoading ? (
              <Loader />
            ) : (
              <div className="flex flex-col gap-3">
                {vps.data?.map((v) => (
                  <div
                    key={v.id}
                    className="relative overflow-hidden rounded border border-line bg-black/20 p-3.5"
                  >
                    <span
                      className="absolute left-0 top-0 h-full w-[3px]"
                      style={{ background: vpsColor(v.alias) }}
                    />
                    <div className="flex flex-wrap items-center gap-3">
                      <VpsLogo alias={v.alias} size="md" />
                      <div className="min-w-0">
                        <div className="font-display text-[14px] font-semibold text-fg">
                          {v.display_name}
                        </div>
                        <div className="font-mono text-[10px] text-muted">
                          {v.region ?? "—"} · {v.stack_type ?? "—"}
                        </div>
                      </div>
                      <div className="ml-auto flex items-center gap-4">
                        <div className="text-right">
                          <div className="hud-label">Events</div>
                          <div className="tabular font-mono text-[13px] font-semibold text-fg">
                            {fmtInt(v.event_count)}
                          </div>
                        </div>
                        {v.has_otx_key && <Badge tone="ops">OTX</Badge>}
                        <div className="flex items-center gap-1.5">
                          <StatusDot status={v.status} />
                          <span
                            className="font-mono text-[10px] font-semibold uppercase"
                            style={{ color: STATUS_COLOR[v.status] }}
                          >
                            {v.status}
                          </span>
                        </div>
                      </div>
                    </div>
                    <div className="mt-2.5 flex items-center gap-2 border-t border-line/60 pt-2 font-mono text-[10px] text-muted">
                      <KeyRound className="h-3 w-3" />
                      <span>key ••••••••••••{v.id.slice(-6)}</span>
                      <span className="ml-auto">last seen {relTime(v.last_seen_at)}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Panel>
        </div>

        {/* Register new sensor */}
        <div className="flex flex-col gap-4">
          <Panel title="Deploy New Sensor" sub="Admin only · onboards a source" icon={<Plus className="h-4 w-4" />}>
            <div className="flex flex-col gap-3">
              <Field label="Alias" value={form.alias} onChange={(v) => setForm({ ...form, alias: v })} placeholder="e.g. HKG" mono />
              <Field
                label="Display Name"
                value={form.display_name}
                onChange={(v) => setForm({ ...form, display_name: v })}
                placeholder="Sentinel — Hong Kong"
              />
              <Field label="Region" value={form.region} onChange={(v) => setForm({ ...form, region: v })} placeholder="Hong Kong, HK" />
              <Field label="Base URL" value={form.base_url} onChange={(v) => setForm({ ...form, base_url: v })} placeholder="http://.../dashboard" mono />
              <div>
                <label className="hud-label mb-1 block">Stack Type</label>
                <select
                  value={form.stack_type}
                  onChange={(e) => setForm({ ...form, stack_type: e.target.value })}
                  className="w-full rounded border border-line bg-panel px-2.5 py-2 font-mono text-[12px] text-fg focus:border-signal/50 focus:outline-none"
                >
                  <option value="html_fastapi">html_fastapi</option>
                  <option value="react_pg">react_pg</option>
                  <option value="other">other</option>
                </select>
              </div>
              <Field
                label="Admin Token"
                value={admin}
                onChange={setAdmin}
                placeholder="paste admin bearer token"
                mono
                secret
              />
              <button
                onClick={() => register.mutate()}
                disabled={!form.alias || !form.display_name || !admin || register.isPending}
                className="mt-1 inline-flex items-center justify-center gap-2 rounded border border-signal/50 bg-signal/15 py-2.5 font-mono text-[12px] font-semibold uppercase tracking-wider text-signal transition-colors hover:bg-signal/25 disabled:cursor-not-allowed disabled:opacity-40"
              >
                <ShieldCheck className="h-4 w-4" />
                {register.isPending ? "Provisioning…" : "Generate API Key"}
              </button>
              {register.isError && (
                <p className="font-mono text-[11px] text-hostile-soft">
                  ✗ {(register.error as Error).message}
                </p>
              )}
            </div>
          </Panel>

          {issued && (
            <Panel title="Sensor Provisioned" icon={<KeyRound className="h-4 w-4" />} className="border-signal/40">
              <p className="mb-2 font-mono text-[11px] text-signal">
                ▸ {issued.alias} — copy this key now. It is not retrievable later.
              </p>
              <div className="flex items-center gap-2 rounded border border-signal/40 bg-black/40 p-2">
                <code className="flex-1 break-all font-mono text-[11px] text-ops">{issued.api_key}</code>
                <button onClick={copyKey} className="shrink-0 rounded border border-line p-1.5 text-dim hover:text-fg">
                  {copied ? <Check className="h-4 w-4 text-ops" /> : <Copy className="h-4 w-4" />}
                </button>
              </div>
              <div className="mt-3">
                <div className="hud-label mb-1 flex items-center gap-1">
                  <Terminal className="h-3 w-3" /> agent/config.yaml
                </div>
                <pre className="overflow-x-auto rounded border border-line bg-void/80 p-2.5 font-mono text-[10.5px] leading-relaxed text-dim">
{`central_url: "https://c2.example/api/v1"
api_key: "${issued.api_key}"
logs_path: "/opt/honeypot/logs/events.log"
batch_interval_seconds: 45`}
                </pre>
              </div>
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}

function Field({
  label,
  value,
  onChange,
  placeholder,
  mono,
  secret,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  mono?: boolean;
  secret?: boolean;
}) {
  return (
    <div>
      <label className="hud-label mb-1 block">{label}</label>
      <input
        type={secret ? "password" : "text"}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className={`w-full rounded border border-line bg-panel px-2.5 py-2 text-[12px] text-fg placeholder:text-muted focus:border-signal/50 focus:outline-none ${
          mono ? "font-mono" : ""
        }`}
      />
    </div>
  );
}
