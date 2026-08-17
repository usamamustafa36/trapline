import Image from "next/image";
import { cn } from "@/lib/utils";
import { VPS_LOGOS, vpsColor } from "@/lib/theme";

type VpsLogoProps = {
  alias: string;
  size?: "sm" | "md" | "lg";
  className?: string;
  showFallback?: boolean;
};

const SIZES = {
  sm: { box: "h-7 w-7", px: 28, image: "h-5 w-5" },
  md: { box: "h-10 w-10", px: 40, image: "h-8 w-8" },
  lg: { box: "h-12 w-12", px: 48, image: "h-10 w-10" },
} as const;

export function VpsLogo({ alias, size = "md", className, showFallback = true }: VpsLogoProps) {
  const src = VPS_LOGOS[alias];
  const s = SIZES[size];

  if (!src) {
    if (!showFallback) return null;
    return (
      <div
        className={cn(
          "grid shrink-0 place-items-center rounded font-display text-[13px] font-bold text-void",
          s.box,
          className,
        )}
        style={{ background: vpsColor(alias) }}
      >
        {alias}
      </div>
    );
  }

  return (
    <div
      className={cn(
        "grid shrink-0 place-items-center overflow-hidden rounded border border-white/10 bg-black/30",
        s.box,
        className,
      )}
    >
      <Image
        src={src}
        alt={`${alias} logo`}
        width={s.px}
        height={s.px}
        className={cn("object-contain", s.image)}
      />
    </div>
  );
}

/** Wordmark rather than a raster asset, so the build carries no deployment branding. */
export function ProjectLogo({ className }: { className?: string }) {
  return (
    <div
      className={cn(
        "relative grid h-9 w-9 shrink-0 place-items-center overflow-hidden rounded-xl border border-white/10 bg-black/30",
        className,
      )}
      aria-label="Trapline"
      role="img"
    >
      <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" aria-hidden="true">
        <path
          d="M4 6h16M4 12h16M4 18h16"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinecap="round"
          className="text-white/25"
        />
        <circle cx="7" cy="6" r="2.1" className="fill-current text-[#57C7FF]" />
        <circle cx="14" cy="12" r="2.1" className="fill-current text-[#33C88A]" />
        <circle cx="10" cy="18" r="2.1" className="fill-current text-[#FF6DA6]" />
      </svg>
    </div>
  );
}
