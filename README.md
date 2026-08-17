# Trapline

> Distributed honeynet telemetry, aggregated into one console.
> Collects JSON-lines events from independent honeypot sensors, normalises them at the edge, and
> correlates attacker activity across the whole fleet.

A trapline is a line of traps checked in sequence. That is what this is: several honeypot sensors
run independently, and one platform tells you what the fleet as a whole is seeing.

## Why it exists

A single honeypot tells you who knocked on one door. A fleet tells you something a single sensor
cannot: whether the same actor is walking the whole street, and how fast. The interesting signal is
not the individual event, it is the correlation across sensors.

Trapline is built around three ideas.

**Push, don't pull. Normalise at the edge.** Each sensor runs a small shipper agent that translates
its local logs into one canonical event format and pushes to the central ingestion API. The central
schema never learns what stack a sensor runs. Onboarding sensor number four is a config file, not a
schema migration.

**Correlation is the product.** Every ingested event upserts into an IP registry with per-sensor
sightings. An address seen by more than one sensor is flagged, and a coordination heuristic
separates addresses that hit multiple sensors within a short window, which reads as scripted or
coordinated reconnaissance, from addresses that hit them months apart, which reads as ordinary
background scanning. Those are different threats and they should not look the same in a dashboard.

**The collector is itself a target.** Every field in an ingested event is attacker-supplied. The
ingestion path treats it that way.

## Threat model for the platform

This is the part most honeypot dashboards skip. If an attacker controls the input to your collector,
your collector is part of the attack surface.

- All event fields are treated as untrusted input.
- Parameterised queries only, via SQLAlchemy Core and ORM. No string-concatenated SQL.
- Per-sensor API keys, hashed at rest, independently rotatable and revocable, so a compromised
  sensor is contained to its own key.
- Per-key rate limiting on the ingestion endpoint.
- Third-party API keys encrypted at rest.

## Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js (App Router), TypeScript, Tailwind, Recharts |
| Backend | FastAPI, SQLAlchemy 2.0, Pydantic v2 |
| Database | PostgreSQL (INET, JSONB, GIN) |
| Ingestion | Push model, per-sensor shipper agents tailing logs |
| Enrichment | AlienVault OTX reputation, cached per address |
| Infra | Docker Compose, Nginx with TLS in production |

Full design in [`architecure.md`](./architecure.md), covering data flow, schema, ingestion API,
deduplication logic, threat-intel integration and the phased delivery plan.

## Quick start

```bash
cp .env.example .env      # then fill in the secrets, see below
docker compose up --build
# Dashboard : http://localhost:3000
# API docs  : http://localhost:8000/docs
```

The schema is created on first boot. **The database starts empty and fills only from real sensor
ingestion.** There is no synthetic demo data in the default configuration.

Before first run, generate real values for these in `.env`:

```bash
# SECRET_KEY
python -c "import secrets; print(secrets.token_urlsafe(64))"
# FERNET_KEY
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

## Connecting a sensor

1. Register the sensor: `POST /api/v1/vps/register`, which returns an API key.
2. Put the key in that host's `agent/config.yaml`.
3. `systemctl enable --now trapline-shipper`.

Events start flowing. No central schema or dashboard change is required. See
[`agent/README.md`](./agent/README.md).

Any sensor works as long as it emits the canonical JSON event shape, so the fleet is not locked to
one honeypot engine. The expected input fields are documented in
[`agent/README.md`](./agent/README.md).

## Local development

**Backend**

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export DATABASE_URL=postgresql+psycopg://trapline:trapline@localhost:5432/trapline
python -m app.seed          # creates schema only
uvicorn app.main:app --reload --port 8000
```

**Frontend**

```bash
cd frontend
npm install
cp .env.local.example .env.local
npm run dev
```

## A note on deployment data

This repository is the platform, not a deployment. It ships no sensor artwork, no host addresses and
no operator identifiers, and the sensor identities in the code (`SENSOR-01` and so on) are
placeholders. Addresses that appear in documentation are from the RFC 5737 ranges reserved for
exactly that purpose and route nowhere.

Point it at your own sensors.

## Licence

MIT.
