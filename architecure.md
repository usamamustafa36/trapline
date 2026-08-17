# Trapline Centralized Monitoring Platform — Technical Design Document

## 0. Context & Sources

The reference deployment this design was written against is a three-sensor fleet. Sensors differ in
how they present and store their own data, which is the integration problem this platform exists to
absorb:

| Sensor | Local frontend | Local backend | Local storage | Shipper variant |
|---|---|---|---|---|
| SENSOR-01 | HTML/CSS/JS | FastAPI | JSON-lines log file | log-tail |
| SENSOR-02 | HTML/CSS/JS | FastAPI | JSON-lines log file | log-tail |
| SENSOR-03 | Next.js | FastAPI | PostgreSQL | Postgres reader |

**Central platform stack:** Next.js (frontend) + FastAPI (backend) + PostgreSQL (DB).

**Key simplification: the sensors share an event vocabulary even when they do not share a stack.**
Whatever emulates the services, each sensor produces structured JSON per event with a common set of
fields (`ID`, `DateTime`, `Description`, `Protocol`, `RemoteAddr`, `SourceIp`, `SourcePort`, `User`,
`Password`, `Status`, `Client`), written to a configurable path. That canonical shape is documented
in [`agent/README.md`](./agent/README.md) and is the platform's only hard input contract.

So the differing stacks (HTML+FastAPI vs Next.js+FastAPI+Postgres) mostly affect how each sensor
renders its *own local* dashboard. They do not affect the raw event source. The shipper agents only
need to speak one language: the canonical event JSON. That is a much smaller integration surface
than originally scoped, and it holds for any future sensor that emits a comparable shape, whatever
honeypot software is behind it.

---

## 1. Guiding Principle

**Push, don't pull. Normalize at the edge, not the core.**

Each VPS runs a small **shipper agent** (regardless of its internal stack) that translates its native logs into a single canonical JSON event format and pushes it to the central ingestion API. The central Postgres DB never needs to know whether an event originated from a React+Postgres honeypot or an HTML+flat-file one — by the time it lands centrally, it's already normalized.

This is what makes the system "agnostic" and future-proof: onboarding VPS #4, #5, #6 later means writing/configuring an agent, not touching the central schema or dashboard code.

---

## 2. Data Flow Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  VPS: SENSOR-01        │     │  VPS: SENSOR-03        │     │  VPS: SENSOR-02        │
│  (React+PG or     │     │  (HTML+FastAPI)  │     │  (React+PG or     │
│   HTML+FastAPI)   │     │                   │     │   HTML+FastAPI)   │
│                   │     │                   │     │                   │
│ ┌───────────────┐ │     │ ┌───────────────┐ │     │ ┌───────────────┐ │
│ │ Shipper Agent │ │     │ │ Shipper Agent │ │     │ │ Shipper Agent │ │
│ │ (Python cron/ │ │     │ │ (Python cron/ │ │     │ │ (Python cron/ │ │
│ │  systemd svc) │ │     │ │  systemd svc) │ │     │ │  systemd svc) │ │
│ └───────┬───────┘ │     │ └───────┬───────┘ │     │ └───────┬───────┘ │
└─────────┼─────────┘     └─────────┼─────────┘     └─────────┼─────────┘
          │  HTTPS POST /api/v1/events  (bearer = per-VPS API key)
          └──────────────────┬──────────────────────────────┘
                              ▼
                  ┌────────────────────────┐
                  │  Central Ingestion API  │
                  │  (FastAPI or Node)      │
                  │  - auth/validate         │
                  │  - dedupe (event UUID)   │
                  │  - normalize/enrich hook │
                  └───────────┬─────────────┘
                              ▼
                  ┌────────────────────────┐
                  │   Central PostgreSQL    │
                  │   (events, ip registry, │
                  │    threat_intel, etc.)  │
                  └───────────┬─────────────┘
                              ▼
                  ┌────────────────────────┐
                  │   React Dashboard        │
                  │   (per-VPS + aggregate)  │
                  └────────────────────────┘
```

**Why push over pull (e.g., CDC/log-tailing from the center):**
- Works identically whether the source is Postgres-backed or flat-file-backed.
- No need to open inbound DB ports on each VPS (better security posture — you don't want your central platform holding credentials to poke into every honeypot's DB).
- Shipper agent can batch, retry, and buffer during network outages.

**Two viable shipper mechanisms, both resting on the shared event vocabulary:**

**Option A — Log-tail agent (simplest, recommended for MVP):**
1. Small Python service (systemd) on each sensor tails the configured JSON-lines event log, reading new lines since a saved byte-offset/inode checkpoint.
2. Maps the canonical input fields (`SourceIp`, `SourcePort`, `Protocol`, `User`, `Password`, `Status`, `DateTime`, `Description`, `ID`) into the central event schema (Section 3.2), generating a stable `event_uuid` (the sensor's own `ID` field works well for this when present).
3. POSTs batches (every 30–60s) to `/api/v1/events` with the sensor's bearer token.
4. Persists checkpoint to disk so restarts don't re-send old lines.
5. Retries with backoff on network failure; buffers to local disk if central is unreachable so nothing is lost.
- Works on file-based and Postgres-backed sensors alike, since the event log exists regardless of what the surrounding app's DB looks like.

**Option B — Message-queue ingestion (better for near-real-time, worth doing in Phase 2/3):**
1. Point each sensor's tracing output at a **central** AMQP broker (or a per-sensor local broker relayed onward), where the honeypot software supports publishing events directly.
2. A consumer service on the central platform subscribes to every queue, normalizes, and writes directly to Postgres — no polling, no log-tailing, no local checkpoint files to manage.
3. Trade-off: requires outbound network access from each sensor to the broker port, and a little more infra to stand up centrally.

Start with **Option A** for the MVP (no changes needed to existing sensor configuration, the agent is just a log reader), and consider migrating to **Option B** once volume and latency needs justify it.

---

## 3. Central PostgreSQL Schema

```sql
-- 3.1 Registered honeypot sources
CREATE TABLE vps_sources (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alias           TEXT UNIQUE NOT NULL,        -- 'SENSOR-01', 'SENSOR-03', 'SENSOR-02'
    display_name    TEXT NOT NULL,
    base_url        TEXT,
    stack_type      TEXT,                        -- 'react_pg' | 'html_fastapi' | future values
    api_key_hash    TEXT NOT NULL,                -- hashed shipper auth token
    alienvault_key_encrypted TEXT,                -- per-VPS OTX key, encrypted at rest
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT now(),
    last_seen_at    TIMESTAMPTZ
);

-- 3.2 Canonical security events (one row per honeypot hit)
CREATE TABLE events (
    id              BIGSERIAL PRIMARY KEY,
    event_uuid      UUID UNIQUE NOT NULL,         -- generated by shipper agent; dedupe key
    vps_id          UUID NOT NULL REFERENCES vps_sources(id),
    occurred_at     TIMESTAMPTZ NOT NULL,          -- event time at the VPS
    received_at     TIMESTAMPTZ DEFAULT now(),     -- ingestion time centrally
    src_ip          INET NOT NULL,
    dst_port        INTEGER,
    protocol        TEXT,                          -- ssh, http, ftp, telnet, etc.
    event_type      TEXT,                           -- login_attempt, scan, payload_upload, etc.
    severity        SMALLINT DEFAULT 0,             -- 0-4 normalized severity
    username_tried  TEXT,
    password_tried  TEXT,
    payload_excerpt TEXT,
    raw_payload     JSONB NOT NULL,                 -- full original event, source-format-agnostic
    country_code    TEXT,                           -- populated by GeoIP enrichment
    created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_events_vps_time ON events (vps_id, occurred_at DESC);
CREATE INDEX idx_events_src_ip ON events (src_ip);
CREATE INDEX idx_events_type ON events (event_type);
CREATE INDEX idx_events_raw_payload_gin ON events USING GIN (raw_payload);

-- 3.3 IP registry — one row per unique IP ever seen, across all VPS
CREATE TABLE ip_registry (
    ip              INET PRIMARY KEY,
    first_seen_at   TIMESTAMPTZ,
    last_seen_at    TIMESTAMPTZ,
    total_events    INTEGER DEFAULT 0,
    vps_count       INTEGER DEFAULT 0,             -- how many distinct VPS have seen this IP
    country_code    TEXT,
    asn             TEXT,
    is_cross_vps    BOOLEAN DEFAULT FALSE          -- convenience flag, vps_count > 1
);

-- 3.4 Join table: which VPS have seen which IP (drives dedup/linking)
CREATE TABLE ip_vps_sightings (
    ip              INET REFERENCES ip_registry(ip),
    vps_id          UUID REFERENCES vps_sources(id),
    first_seen_at   TIMESTAMPTZ,
    last_seen_at    TIMESTAMPTZ,
    event_count     INTEGER DEFAULT 0,
    PRIMARY KEY (ip, vps_id)
);

-- 3.5 AlienVault / OTX threat intel enrichment cache
CREATE TABLE threat_intel (
    ip              INET PRIMARY KEY REFERENCES ip_registry(ip),
    otx_pulse_count INTEGER DEFAULT 0,
    reputation_score NUMERIC,
    tags            TEXT[],
    malware_families TEXT[],
    last_checked_at TIMESTAMPTZ,
    checked_via_vps UUID REFERENCES vps_sources(id),  -- which VPS's OTX key was used
    raw_response    JSONB
);
```

**Design notes:**
- `raw_payload JSONB` preserves the sensor's event exactly as emitted (`ID`, `DateTime`, `Description`, `Protocol`, `RemoteAddr`, `SourceIp`, `SourcePort`, `User`, `Password`, `Status`, `Client`, etc.) — this is your safety net if the normalized columns miss a field you later care about, and it's what makes onboarding a future sensor painless as long as it emits a comparable JSON shape.
- Canonical field mapping from the sensor event → `events`: `SourceIp`→`src_ip`, `SourcePort`→(store in raw, optional column), `Protocol`→`protocol`, `User`→`username_tried`, `Password`→`password_tried`, `DateTime`→`occurred_at`, `Description`/`Msg`→`event_type` (needs light normalization, since `Description` is a free-text string that varies per emulated service, e.g. "SSH interactive ubuntu" — worth mapping to a small controlled vocabulary like `ssh_login_attempt`, `http_scan`, `telnet_login_attempt` in the shipper agent).
- `ip_registry` + `ip_vps_sightings` is the backbone of cross-VPS IP linking (Section 5).
- Partitioning `events` by month (Postgres native partitioning) is worth doing once volume grows — flagged in Section 8.

---

## 4. Ingestion API Design

**Base URL:** `https://your-central-platform/api/v1`

### `POST /api/v1/events` — bulk event ingestion
- **Auth:** `Authorization: Bearer <per-VPS API key>` — key maps to `vps_sources.api_key_hash`.
- **Body:**
```json
{
  "events": [
    {
      "event_uuid": "b3f1...",
      "occurred_at": "2026-07-11T08:12:00Z",
      "src_ip": "185.220.101.4",
      "dst_port": 22,
      "protocol": "ssh",
      "event_type": "login_attempt",
      "username_tried": "admin",
      "password_tried": "123456",
      "payload_excerpt": null,
      "raw": { "...original VPS-native event, untouched..." }
    }
  ]
}
```
- **Response:** `202 Accepted` with per-event ack/reject status (rejects only on validation failure or duplicate `event_uuid`).
- Idempotent by `event_uuid` — safe for the agent to retry a batch after a timeout.
- Batches capped (e.g., 500 events/request) to keep payloads sane.

### `POST /api/v1/vps/register` (admin-only)
Registers a new VPS source, generates and returns its API key. This is the "no code changes to onboard a new VPS" mechanism — an admin fills a form in the dashboard, gets a key, drops it into the new VPS's shipper agent config, done.

### `GET /api/v1/vps/{alias}/health`
Shipper agents can heartbeat here; updates `last_seen_at`, powers a "VPS online/stale/offline" indicator on the dashboard.

### Internal-only (dashboard → central API):
- `GET /api/v1/events?vps=&type=&from=&to=&ip=&page=`
- `GET /api/v1/ips/{ip}` — full cross-VPS profile for one IP
- `GET /api/v1/ips/cross-vps` — list of IPs seen on 2+ VPS
- `GET /api/v1/stats/overview` and `/api/v1/stats/{vps_alias}`
- `GET /api/v1/reports/export?format=csv|pdf&...`

---

## 5. IP Deduplication & Cross-VPS Linking Logic

On every ingested event, a lightweight trigger/worker does:

1. `UPSERT` into `ip_registry` (increment `total_events`, update `last_seen_at`).
2. `UPSERT` into `ip_vps_sightings` for `(ip, vps_id)`.
3. Recompute `vps_count` for that IP = `COUNT(DISTINCT vps_id)` from `ip_vps_sightings`.
4. If `vps_count > 1`, set `is_cross_vps = TRUE`.

This can run as a Postgres trigger on `events` insert (simplest, keeps logic in the DB) or as a small async worker consuming from a queue (better if you later add heavier enrichment steps). For MVP, a trigger is simplest and fast enough.

**Cross-VPS IP profile view** (what the dashboard shows when you click an IP):
- Timeline of all events for that IP, across every VPS, merged and sorted.
- Which VPS saw it first, which saw it most.
- Threat intel panel (AlienVault data, Section 6).
- A simple "coordination score" heuristic — e.g., flag IPs that hit 2+ VPS within a short time window (e.g., <24h) as likely scripted/coordinated recon vs. IPs that hit multiple VPS months apart (probably just a broad internet scanner).

---

## 6. AlienVault (OTX) Integration

**Ownership model:** each VPS keeps its own OTX API key (as you specified), stored encrypted in `vps_sources.alienvault_key_encrypted`.

**How enrichment works:**
1. A central enrichment worker (scheduled job, e.g. every 15 min) pulls IPs from `ip_registry` that are new or stale (`last_checked_at` older than a threshold).
2. For each IP, it selects **one of the VPS's OTX keys** to make the lookup — the sensible default is "use the key belonging to the VPS that most recently saw this IP," which keeps quota usage spread across your available keys and satisfies the "individual level" ownership you described.
3. Response (pulse count, reputation, malware family tags, associated indicators) is cached into `threat_intel`, keyed by IP — not by VPS — since threat intel about an IP is a global fact, not a per-VPS one.
4. `checked_via_vps` records which key was used, purely for audit/quota tracking.

**How it enriches the dashboard:**
- **Threat badge** on any event/IP row: "Known malicious (OTX: 12 pulses)" vs "No known reputation."
- **Reputation score** column sortable in the events table and IP list — lets analysts triage "novel/unknown IP" vs "known botnet member" at a glance.
- **Tag chips** (e.g., `mirai`, `bruteforce`, `scanner`) surfaced on the IP profile page.
- Cross-VPS IPs with a bad OTX reputation are the highest-priority items — worth a dedicated "Priority Watchlist" widget on the aggregate dashboard (cross-VPS + known-malicious).

---

## 7. React Dashboard — Layout & Key Components

```
/                     → Aggregate Overview (default landing page)
/vps/:alias           → Individual VPS view (SENSOR-01 / SENSOR-03 / SENSOR-02 / future)
/ips/cross-vps         → Cross-VPS IP list
/ips/:ip               → Single IP deep-dive profile
/reports               → Report builder / export
/settings/vps          → Manage VPS sources, API keys, health status
```

**Aggregate Overview (`/`):**
- KPI strip: total events (24h/7d/30d), active VPS count, unique attacking IPs, cross-VPS IP count.
- Attack timeline chart (stacked by VPS, toggleable) — line/area chart.
- Top 10 threat IPs table (with OTX reputation badge, cross-VPS flag).
- Geographic distribution map (country_code → choropleth or bubble map).
- Event-type breakdown (pie/bar — SSH brute force vs HTTP scan vs upload attempts, etc.).
- VPS health strip (online/stale/offline per source, last event received).

**Individual VPS view (`/vps/:alias`):**
- Same widget set, scoped to `vps_id` — lets an analyst focused on "just SENSOR-03" see only that.
- Raw event table with filters (time range, event type, IP, port).

**Cross-VPS IP list (`/ips/cross-vps`):**
- Table: IP, VPS count, VPS names, total events, first/last seen, OTX reputation.
- Sortable/filterable; clicking a row opens the IP profile.

**IP profile (`/ips/:ip`):**
- Merged cross-VPS timeline.
- Per-VPS breakdown (which VPS, how many hits, what protocols/ports).
- OTX threat intel panel.
- "Related IPs" (same /24 subnet or ASN, if you want to extend later).

**Reports (`/reports`):**
- Filter builder: date range, VPS(s), event type, IP, severity.
- Export as CSV/PDF; scheduled email reports are a good Phase 2 addition.

**Confirmed stack for the central platform:** Next.js (App Router) for the dashboard, FastAPI for the ingestion + query API, PostgreSQL for storage — mirroring SENSOR-03's existing stack so patterns and even some code (Pydantic models, DB access patterns) can be reused. Recommended libraries: TanStack Query (API caching/polling from Next.js to FastAPI), Recharts (charts), TanStack Table (event tables), Tailwind/shadcn for UI consistency.

---

## 8. Deployment & Scaling Considerations

**MVP deployment (small scale, 3 VPS):**
- Central platform: single VPS/VM running Docker Compose — `central-api` (FastAPI or Node), `central-db` (Postgres), `dashboard` (React static build behind Nginx), reverse-proxied with TLS (Let's Encrypt).
- Shipper agents: a small Python script + systemd timer on each source VPS. No heavy dependencies — `requests` + a checkpoint file is enough.
- IP dedup via Postgres trigger (Section 5) — no external queue needed yet.
- AlienVault enrichment as a cron job (e.g. every 15 min) — simple `pg_cron` or a systemd timer hitting an internal endpoint.

**Scaling triggers & what to add when you hit them:**
| Symptom | Add |
|---|---|
| Events table > tens of millions of rows, queries slow | Partition `events` by month (native Postgres declarative partitioning); archive old partitions to cold storage |
| More than ~10-15 VPS, or need near-real-time (<5s) ingestion | Move ingestion from HTTP-batch to a message queue (RabbitMQ/Redis Streams) between agents and the DB writer, so ingestion API just enqueues and a worker pool writes |
| Dashboard queries getting slow under concurrent users | Add materialized views for the aggregate stats (refreshed every N minutes) instead of live aggregation queries |
| Need alerting (e.g. Slack/email on new cross-VPS malicious IP) | Add a rules engine / notification service subscribing to new `threat_intel` writes |
| Multiple analysts, need access control | Add RBAC — read-only vs admin, and optionally per-VPS scoped access |

**Security considerations specific to this system:**
- Ingestion API must treat all inbound event data as **untrusted input** — it's literally attacker-supplied strings (usernames, passwords, payload excerpts) flowing from a honeypot. Strict parameterized queries (never string-concatenate into SQL), and sanitize before rendering in the React dashboard (avoid dangerouslySetInnerHTML on any field derived from `raw_payload`).
- Per-VPS API keys should be rotatable independently, and revocable from `/settings/vps` without redeploying anything.
- Store `alienvault_key_encrypted` with actual encryption (e.g., libsodium/KMS-backed), not just base64.
- Rate-limit the ingestion endpoint per VPS key to stop one compromised/misbehaving shipper from flooding the DB.

---

## 9. Phased Delivery Plan

**Phase 1 — MVP (get real data flowing)**
1. Central Postgres schema (Section 3) + Docker Compose skeleton.
2. Ingestion API: `POST /api/v1/events`, `POST /api/v1/vps/register`.
3. Shipper agent template — build once, configure per VPS. First task once we're in VS Code: inspect what SENSOR-01/SENSOR-03/SENSOR-02 actually expose (confirm which stack each one runs) so we know whether the agent reads Postgres directly or scrapes/reads the FastAPI's log store.
4. IP registry + cross-VPS trigger logic.
5. Dashboard: Aggregate Overview + Individual VPS view + basic event table. No AlienVault yet.

**Phase 2 — Intelligence layer**
6. AlienVault/OTX enrichment worker + threat_intel schema (already scaffolded above).
7. Cross-VPS IP list + IP profile page.
8. GeoIP enrichment for the map widget.
9. Reports/export.

**Phase 3 — Scale & polish**
10. Queue-based ingestion if volume warrants it.
11. Alerting/notifications.
12. RBAC + multi-analyst support.
13. Partitioning/archival for `events`.

---

## 10. Deployment checklist

Central platform is Next.js + FastAPI + PostgreSQL. Per sensor, confirm before provisioning:

1. The exact path the sensor writes its JSON-lines event log to, or its database DSN for
   Postgres-backed sensors.
2. A host for the central platform, with capacity to run Postgres, FastAPI and Next.js.
3. Outbound network access from every sensor to the central host on the ingestion API port. Needed
   for the log-tail agent, and equally for the message-queue option later.
4. TLS termination and an authentication layer in front of the read API before the console is
   reachable from anywhere untrusted. The ingestion path is authenticated per sensor; the read path
   is not authenticated by default and must not be exposed as-is.

**Build order:**
1. Provision the new central VPS (Docker, Postgres, reverse proxy/TLS).
2. Central Postgres schema (Section 3).
3. FastAPI ingestion API (`/api/v1/events`, `/api/v1/vps/register`) + auth.
4. Shipper agent (Option A, log-tail) — build once, deploy to SENSOR-01 first (simplest, file-based), verify events land centrally, then repeat on SENSOR-02 and SENSOR-03.
5. Next.js dashboard skeleton: Aggregate Overview + Individual VPS view + raw event table.
6. IP registry/cross-VPS trigger logic.
7. AlienVault enrichment worker (Phase 2).