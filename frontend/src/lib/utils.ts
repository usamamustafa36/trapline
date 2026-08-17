import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function fmtInt(n: number | null | undefined): string {
  if (n == null) return "—";
  return n.toLocaleString("en-US");
}

export function fmtCompact(n: number | null | undefined): string {
  if (n == null) return "—";
  return Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 }).format(n);
}

export function relTime(iso: string | null | undefined): string {
  if (!iso) return "never";
  const then = new Date(iso).getTime();
  const secs = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days}d ago`;
  return `${Math.floor(days / 30)}mo ago`;
}

export function fmtTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("en-GB", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

export function fmtClock(d: Date): string {
  return d.toLocaleTimeString("en-GB", { hour12: false });
}

// ISO-3166 alpha-2 → flag emoji.
export function flag(cc: string | null | undefined): string {
  if (!cc || cc.length !== 2) return "🏴";
  const A = 0x1f1e6;
  return String.fromCodePoint(
    ...cc.toUpperCase().split("").map((c) => A + c.charCodeAt(0) - 65),
  );
}

const COUNTRY_NAMES: Record<string, string> = {
  CN: "China", RU: "Russia", US: "United States", IN: "India", BR: "Brazil",
  VN: "Vietnam", ID: "Indonesia", KR: "South Korea", DE: "Germany", NL: "Netherlands",
  IR: "Iran", TW: "Taiwan", UA: "Ukraine", GB: "United Kingdom", FR: "France",
  SG: "Singapore", TR: "Türkiye", RO: "Romania", HK: "Hong Kong", KP: "North Korea",
  CA: "Canada", PK: "Pakistan",
};
export function countryName(cc: string | null | undefined): string {
  if (!cc) return "Unknown";
  return COUNTRY_NAMES[cc.toUpperCase()] ?? cc;
}

// Country centroids [lon, lat] for the tactical world plot / globe.
export const COUNTRY_CENTROID: Record<string, [number, number]> = {
  CN: [104, 35], RU: [90, 62], US: [-98, 39], IN: [79, 22], BR: [-52, -10],
  VN: [106, 16], ID: [113, -2], KR: [128, 36], DE: [10, 51], NL: [5, 52],
  IR: [53, 32], TW: [121, 24], UA: [32, 49], GB: [-2, 54], FR: [2, 47],
  SG: [104, 1], TR: [35, 39], RO: [25, 46], HK: [114, 22], KP: [127, 40],
  CA: [-95, 57], PK: [69, 30],
  // Extended coverage
  MY: [102, 4], TH: [101, 15], JP: [138, 37], PH: [122, 12], BD: [90, 24],
  SA: [45, 24], EG: [30, 26], PL: [19, 52], IT: [12, 42], ES: [-4, 40],
  MX: [-102, 23], AR: [-64, -34], ZA: [24, -29], NG: [8, 10], SE: [16, 62],
  CH: [8, 47], BE: [4, 51], AT: [14, 47], CZ: [15, 50], FI: [26, 64],
  NO: [9, 62], DK: [10, 56], PT: [-8, 39], GR: [22, 39], IL: [35, 31],
  AE: [54, 24], LK: [81, 7], NP: [84, 28], MM: [96, 21], KH: [105, 12],
  KZ: [67, 48], CO: [-73, 4], CL: [-71, -35], PE: [-75, -10], VE: [-66, 7],
  MA: [-6, 32], DZ: [3, 28], KE: [38, 0], IE: [-8, 53], HU: [19, 47],
  BG: [25, 43], RS: [21, 44], HR: [16, 45], SK: [19, 49], LT: [24, 55],
  IQ: [44, 33], SY: [39, 35], AZ: [48, 40], UZ: [64, 42], AU: [134, -25],
  NZ: [172, -41], BY: [28, 53], GE: [43, 42], JO: [36, 31], LB: [36, 34],
};

export function scoreLabel(score: number): { label: string; color: string } {
  if (score >= 70) return { label: "COORDINATED", color: "#FF4D6D" };
  if (score >= 40) return { label: "SUSPECT", color: "#FFC24B" };
  if (score >= 15) return { label: "LINKED", color: "#54AEFF" };
  return { label: "SCATTERED", color: "#6C82A0" };
}
