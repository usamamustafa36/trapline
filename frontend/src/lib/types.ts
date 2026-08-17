// Mirrors backend Pydantic schemas (app/schemas.py).

export type VpsStatus = "online" | "stale" | "offline";

export interface Vps {
  id: string;
  alias: string;
  display_name: string;
  base_url: string | null;
  stack_type: string | null;
  region: string | null;
  lat: number | null;
  lon: number | null;
  is_active: boolean;
  last_seen_at: string | null;
  has_otx_key: boolean;
  status: VpsStatus;
  event_count: number;
}

export interface VpsHealth {
  alias: string;
  status: VpsStatus;
  last_seen_at: string | null;
  seconds_since: number | null;
}

export interface EventRow {
  id: number;
  event_uuid: string;
  vps_id: string;
  vps_alias: string | null;
  occurred_at: string;
  received_at: string;
  src_ip: string;
  dst_port: number | null;
  protocol: string | null;
  event_type: string | null;
  severity: number;
  username_tried: string | null;
  password_tried: string | null;
  payload_excerpt: string | null;
  country_code: string | null;
}

export interface PagedEvents {
  total: number;
  page: number;
  page_size: number;
  items: EventRow[];
  is_estimate: boolean;
}

export interface CrossVpsIp {
  ip: string;
  vps_count: number;
  vps_aliases: string[];
  total_events: number;
  first_seen_at: string | null;
  last_seen_at: string | null;
  country_code: string | null;
  otx_pulse_count: number | null;
  reputation_score: number | null;
  coordination_score: number;
}

export interface ThreatIntel {
  otx_pulse_count: number;
  reputation_score: number | null;
  tags: string[] | null;
  malware_families: string[] | null;
  last_checked_at: string | null;
}

export interface VpsBreakdown {
  vps_alias: string;
  display_name: string;
  event_count: number;
  first_seen_at: string | null;
  last_seen_at: string | null;
  protocols: Record<string, number>;
}

export interface IpProfile {
  ip: string;
  first_seen_at: string | null;
  last_seen_at: string | null;
  total_events: number;
  vps_count: number;
  is_cross_vps: boolean;
  country_code: string | null;
  asn: string | null;
  vps_breakdown: VpsBreakdown[];
  threat_intel: ThreatIntel | null;
  coordination_score: number;
  recent_events: EventRow[];
}

export interface Kpi {
  events_24h: number;
  events_7d: number;
  events_30d: number;
  events_all: number;
  active_vps: number;
  total_vps: number;
  unique_ips: number;
  cross_vps_ips: number;
  known_malicious_ips: number;
}

export interface TimelinePoint {
  bucket: string;
  counts: Record<string, number>;
}

export interface NamedCount {
  name: string;
  count: number;
}

export interface GeoCount {
  country_code: string;
  count: number;
}

export interface StatsOverview {
  kpi: Kpi;
  timeline: TimelinePoint[];
  top_ips: CrossVpsIp[];
  event_types: NamedCount[];
  protocols: NamedCount[];
  geo: GeoCount[];
  vps_health: VpsHealth[];
  top_credentials: NamedCount[];
}

export type Window = "24h" | "7d" | "30d" | "all";


// ── Analysis ───────────────────────────────────────────────────────────────────

export type SensorWindow = {
  alias: string;
  events: number;
  first: string;
  last: string;
  days: number;
  addresses: number;
};

export type CoordinatedAddress = {
  ip: string;
  verdict: string;
  sensors: string[];
  order: string[];
  span_seconds: number;
  max_lag_seconds: number;
  events: number;
};

export type CommandPhase = {
  label: string;
  detail: string;
  count: number;
  evidence: string[];
  attck: string | null;
  sources: number;
  techniques: { attck: string; label: string; count: number }[];
};

export type LadderGroup = {
  ladder: string[];
  ladder_length: number;
  addresses: string[];
  address_count: number;
};

export type DatasetInfo = {
  archived: boolean;
  window_start: string | null;
  window_end: string | null;
  days: number;
};

export type AnalysisOverview = {
  events: number;
  addresses: number;
  dataset: DatasetInfo;
  sensors: SensorWindow[];
};

export type AnalysisReport = {
  overview: AnalysisOverview;
  coordination: {
    multi_sensor_addresses: number;
    verdicts: Record<string, number>;
    addresses: CoordinatedAddress[];
  };
  clients: {
    buckets: Record<string, { events: number; addresses: number; share: number; clients: string[] }>;
    clients: { client: string; events: number; addresses: number; bucket: string }[];
    total_events: number;
  };
  credentials: {
    sources_with_ladders: number;
    shared_ladder_groups: number;
    groups: LadderGroup[];
    top_passwords: [string, number][];
    top_usernames: [string, number][];
  };
  guessing: {
    styles: Record<string, number>;
    sources: { ip: string; style: string; attck: string | null; usernames: number; passwords: number; attempts: number }[];
  };
  commands: {
    total_command_events: number;
    classified: number;
    phases: CommandPhase[];
    techniques: [string, number][];
    unmatched_top: [string, number][];
  };
  rhythm: {
    by_hour_utc: number[];
    coefficient_of_variation: number;
    reading: string;
    peak_hour_utc: number;
    trough_hour_utc: number;
  };
  http: {
    top_paths: { uri: string; count: number }[];
    top_user_agents: { agent: string; count: number }[];
  };
};

export type SigmaRule = {
  title: string;
  id: string;
  description: string;
  level: string;
  tags: string[];
  logsource: Record<string, string>;
  detection: Record<string, unknown>;
  falsepositives: string[];
  trapline_evidence: Record<string, unknown>;
};

export type Blocklist = {
  generated: string;
  total: number;
  high_confidence: number;
  entries: { ip: string; confidence: number; reason: string; sensors: string[]; events: number }[];
  nftables: string;
  note: string;
};
