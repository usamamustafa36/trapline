export function ClassificationBar() {
  return (
    <div className="flex h-7 items-center justify-center gap-3 border-b border-white/5 bg-white/[0.02] px-4 text-[10px] font-medium uppercase tracking-[0.28em] text-muted backdrop-blur-sm">
      <span className="hidden items-center gap-1.5 sm:inline-flex">
        <span className="h-1.5 w-1.5 rounded-full bg-ops shadow-glow-ops" />
        Systems Operational
      </span>
      <span className="bg-gradient-to-r from-signal via-recon to-ops bg-clip-text font-semibold text-transparent">
        Trapline · Threat Intelligence
      </span>
      <span className="hidden sm:inline">Secure Session</span>
    </div>
  );
}
