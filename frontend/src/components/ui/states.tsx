import { Loader2, SignalZero, Inbox } from "lucide-react";

export function Loader({ label = "Acquiring telemetry…" }: { label?: string }) {
  return (
    <div className="flex h-40 flex-col items-center justify-center gap-3 text-muted">
      <Loader2 className="h-6 w-6 animate-spin text-signal/70" />
      <span className="hud-label">{label}</span>
    </div>
  );
}

export function ErrorState({ message }: { message?: string }) {
  return (
    <div className="flex h-40 flex-col items-center justify-center gap-2 text-center text-muted">
      <SignalZero className="h-7 w-7 text-hostile/80" />
      <div className="hud-label text-hostile-soft">Uplink Fault</div>
      <p className="max-w-sm font-mono text-[11px] text-dim">
        {message ?? "Central API unreachable. Verify the ingestion service is online."}
      </p>
    </div>
  );
}

export function Empty({ label = "No signals in range" }: { label?: string }) {
  return (
    <div className="flex h-32 flex-col items-center justify-center gap-2 text-muted">
      <Inbox className="h-6 w-6 opacity-60" />
      <span className="hud-label">{label}</span>
    </div>
  );
}
