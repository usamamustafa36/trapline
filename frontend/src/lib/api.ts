import type {
  AnalysisOverview,
  AnalysisReport,
  Blocklist,
  SigmaRule,
  CrossVpsIp,
  IpProfile,
  PagedEvents,
  StatsOverview,
  Vps,
  Window,
} from "./types";

const BASE =
  process.env.NEXT_PUBLIC_API_BASE?.replace(/\/$/, "") ?? "http://localhost:8000/api/v1";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

/**
 * Build a request URL that works whether `NEXT_PUBLIC_API_BASE` is absolute
 * ("https://api.example.com/api/v1") or relative ("/api/v1", used when the console
 * serves its own data). `new URL()` throws on a relative string with no base, so a
 * relative base is resolved against the current origin.
 */
function requestUrl(path: string): URL {
  const target = `${BASE}${path}`;
  if (/^https?:\/\//i.test(target)) return new URL(target);
  const origin =
    typeof window !== "undefined" ? window.location.origin : "http://localhost";
  return new URL(target, origin);
}

async function get<T>(path: string, params?: Record<string, string | number | undefined>): Promise<T> {
  const url = requestUrl(path);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== "" && v !== null) url.searchParams.set(k, String(v));
    }
  }
  const res = await fetch(url.toString(), { headers: { Accept: "application/json" } });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail ?? detail;
    } catch {
      /* ignore */
    }
    throw new ApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}

export const api = {
  base: BASE,
  health: () => get<{ status: string; version: string }>("/health"),
  overview: (window: Window) => get<StatsOverview>("/stats/overview", { window }),
  vpsStats: (alias: string, window: Window) => get<StatsOverview>(`/stats/${alias}`, { window }),
  listVps: () => get<Vps[]>("/vps"),
  events: (params: Record<string, string | number | undefined>) =>
    get<PagedEvents>("/events", params),
  crossVps: (min_vps = 2) => get<CrossVpsIp[]>("/ips/cross-vps", { min_vps }),
  ipProfile: (ip: string) => get<IpProfile>(`/ips/${encodeURIComponent(ip)}`),

  // Analysis and generated detection content.
  analysisReport: () => get<AnalysisReport>("/analysis/report"),
  analysisOverview: () => get<AnalysisOverview>("/analysis/overview"),
  sigmaRules: () => get<{ count: number; rules: SigmaRule[] }>("/detections/sigma"),
  sigmaYamlUrl: () => `${BASE}/detections/sigma.yml`,
  blocklist: () => get<Blocklist>("/detections/blocklist"),

  registerVps: async (
    payload: Record<string, unknown>,
    adminToken: string,
  ): Promise<{ id: string; alias: string; api_key: string; message: string }> => {
    const res = await fetch(`${BASE}/vps/register`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      let detail = res.statusText;
      try {
        detail = (await res.json()).detail ?? detail;
      } catch {
        /* ignore */
      }
      throw new ApiError(res.status, detail);
    }
    return res.json();
  },
};
