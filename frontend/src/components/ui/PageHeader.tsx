export function PageHeader({
  eyebrow,
  title,
  children,
}: {
  eyebrow: string;
  title: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
      <div>
        <div className="mb-2.5 inline-flex items-center gap-2 rounded-full border border-white/[0.07] bg-white/[0.03] py-1 pl-2 pr-3">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-signal shadow-glow-signal" />
          <span className="font-mono text-[10px] font-medium uppercase tracking-[0.14em] text-dim">
            {eyebrow}
          </span>
        </div>
        <h1 className="font-display text-[28px] font-bold tracking-[-0.02em] text-fg">{title}</h1>
      </div>
      {children && <div className="flex items-center gap-2">{children}</div>}
    </div>
  );
}
