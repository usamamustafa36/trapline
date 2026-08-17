import { cn } from "@/lib/utils";

interface PanelProps {
  title?: string;
  sub?: string;
  right?: React.ReactNode;
  icon?: React.ReactNode;
  bracketed?: boolean;
  scanlines?: boolean;
  className?: string;
  bodyClassName?: string;
  children: React.ReactNode;
}

export function Panel({
  title,
  sub,
  right,
  icon,
  bracketed,
  scanlines,
  className,
  bodyClassName,
  children,
}: PanelProps) {
  return (
    <section
      className={cn(
        "panel flex flex-col hover:border-white/[0.1] hover:shadow-card-hover",
        bracketed && "bracketed",
        scanlines && "scanlines overflow-hidden",
        className,
      )}
    >
      {(title || right) && (
        <header className="flex items-center gap-3 border-b border-white/[0.05] px-4 py-3">
          {icon && (
            <span className="icon-chip h-8 w-8 text-signal">{icon}</span>
          )}
          <div className="min-w-0">
            {title && (
              <h2 className="font-display text-[13.5px] font-semibold tracking-[0.005em] text-fg">
                {title}
              </h2>
            )}
            {sub && <p className="hud-label mt-0.5 truncate">{sub}</p>}
          </div>
          {right && <div className="ml-auto flex items-center gap-2">{right}</div>}
        </header>
      )}
      <div className={cn("flex-1 p-4", bodyClassName)}>{children}</div>
    </section>
  );
}
