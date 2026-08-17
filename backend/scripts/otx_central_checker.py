#!/usr/bin/env python3
"""
AlienVault OTX IP Reputation Checker — adapted for Trapline C2.

Based on docs/updated_IP_Checker/check_ips_otx.py. Same classification +
parallel OTX lookups. Tweaked to:
  * pull pending IPs from the central Postgres `ip_registry`
  * write verdicts into `threat_intel` (dashboard "Known Malicious")
  * keep running (--watch) so newly seen IPs are checked automatically

Usage:
  OTX_API_KEY=... python backend/scripts/otx_central_checker.py --from-db --watch --workers 50
"""

from __future__ import annotations

import argparse
import atexit
import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import psycopg
import requests

OTX_BASE_URL = "https://otx.alienvault.com/api/v1"
_print_lock = threading.Lock()
_db_lock = threading.Lock()

MALICIOUS_TAG_KEYWORDS = {
    "malicious",
    "malware",
    "trojan",
    "ransomware",
    "c2",
    "c&c",
    "command_and_control",
    "botnet",
    "phishing",
    "exploit",
    "backdoor",
    "blocklist",
    "threat-intel",
    "threat_intel",
    "compromised",
    "spam",
    "bruteforce",
    "brute-force",
}

BOT_TAG_KEYWORDS = {
    "scanner",
    "scan",
    "scanning",
    "bot",
    "crawler",
    "crawl",
    "spider",
    "brute",
    "bruteforce",
    "ssh",
    "automated",
    "masscan",
    "nmap",
}

HOSTING_ASN_KEYWORDS = {
    "ovh",
    "hetzner",
    "digitalocean",
    "linode",
    "amazon",
    "google cloud",
    "microsoft",
    "azure",
    "vultr",
    "contabo",
    "choopa",
    "leaseweb",
    "m247",
    "hosting",
    "datacenter",
    "data center",
    "cloud",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check IPs against AlienVault OTX and store results in Trapline C2."
    )
    parser.add_argument(
        "--from-db",
        action="store_true",
        help="Load pending IPs from the central Postgres ip_registry (required for C2 mode)",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Keep running: after the backfill, poll for new unchecked IPs",
    )
    parser.add_argument(
        "--watch-interval",
        type=float,
        default=20.0,
        help="Seconds between polls in --watch mode when the queue is empty (default: 20)",
    )
    parser.add_argument(
        "--database-url",
        default=os.environ.get(
            "DATABASE_URL",
            "postgresql://trapline:change-me@127.0.0.1:5433/trapline",
        ),
        help="Postgres URL (or set DATABASE_URL). Accepts postgresql+psycopg:// form.",
    )
    parser.add_argument(
        "--input",
        "-i",
        default="",
        help="Optional CSV/Excel input (legacy mode). Prefer --from-db for C2.",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="/home/asimzaman/Trapline_C-C/.logs/otx_analysis_results.xlsx",
        help="Output Excel file path",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("OTX_API_KEY", ""),
        help="OTX API key (or set OTX_API_KEY environment variable)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Seconds to wait after each API call per worker (default: 0.0)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=90.0,
        help="HTTP request timeout in seconds (default: 90)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Process only the first N IPs (0 = all)",
    )
    parser.add_argument(
        "--checkpoint",
        default="/home/asimzaman/Trapline_C-C/.logs/otx_checkpoint.csv",
        help="Checkpoint CSV saved after each IP",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from checkpoint and skip IPs already processed",
    )
    parser.add_argument(
        "--fetch-malware",
        action="store_true",
        help="Also query OTX malware section (slower; off by default)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Generate Excel results after every N IPs (default: 100)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=50,
        help="Number of parallel threads for OTX lookups (default: 50)",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=500,
        help="How many pending DB IPs to pull per wave in --watch mode (default: 500)",
    )
    return parser.parse_args()


def dsn_from_url(url: str) -> str:
    """Convert sqlalchemy-style postgresql+psycopg:// to a plain psycopg DSN."""
    u = url.replace("postgresql+psycopg://", "postgresql://", 1)
    return u


def connect_db(database_url: str):
    return psycopg.connect(dsn_from_url(database_url), autocommit=False)


def load_pending_ips_from_db(database_url: str, limit: int = 0) -> pd.DataFrame:
    """
    Pending = in ip_registry but not yet in threat_intel.
    Uses ip_registry.total_events as attack_count (fast — no events scan).
    Newest IPs first so live events jump the queue.
    """
    lim_sql = f"LIMIT {int(limit)}" if limit and limit > 0 else ""
    # Skip the top-protocol subquery on large backfills — attack_count alone
    # is enough for classification and keeps the load near-instant.
    sql = f"""
        SELECT host(r.ip) AS source_ip,
               COALESCE(r.total_events, 0)::int AS attack_count,
               '' AS top_protocol
        FROM ip_registry r
        LEFT JOIN threat_intel t ON t.ip = r.ip
        WHERE t.ip IS NULL
          AND NOT (r.ip << '10.0.0.0/8'::inet
                OR r.ip << '172.16.0.0/12'::inet
                OR r.ip << '192.168.0.0/16'::inet
                OR r.ip << '127.0.0.0/8'::inet
                OR r.ip << '::1/128'::inet
                OR r.ip << 'fc00::/7'::inet)
        ORDER BY r.last_seen_at DESC NULLS LAST
        {lim_sql}
    """
    with connect_db(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(sql)
            rows = cur.fetchall()
            cols = [d.name for d in cur.description]
    return pd.DataFrame(rows, columns=cols)


def upsert_threat_intel_row(database_url: str, result: dict[str, Any]) -> None:
    """Write one OTX verdict into threat_intel (thread-safe)."""
    ip = str(result.get("source_ip", "")).strip()
    if not ip:
        return

    status = str(result.get("malicious_status") or "")
    if status == "Error":
        return  # leave unchecked so --watch can retry

    is_malicious = status in {
        "Malicious",
        "Suspicious",
        "Suspicious (Scanner/Bot)",
    }
    pulse_count = int(result.get("pulse_count") or 0)
    if is_malicious and pulse_count == 0:
        pulse_count = 1

    tags_raw = str(result.get("otx_tags") or "").strip()
    tags = [t.strip() for t in tags_raw.split(",") if t.strip()] or None

    rep = result.get("otx_reputation_score")
    try:
        reputation = float(rep) if rep is not None and rep != "" else None
    except (TypeError, ValueError):
        reputation = None

    now = datetime.now(timezone.utc)
    raw = {
        "is_malicious": is_malicious,
        "malicious_status": status,
        "ip_type": result.get("ip_type"),
        "malware_sample_count": int(result.get("malware_sample_count") or 0),
        "asn": result.get("asn") or None,
        "country_name": result.get("otx_country") or None,
        "attack_count": int(result.get("attack_count") or 0),
        "top_protocol": result.get("top_protocol") or None,
        "pulse_names": result.get("pulse_names") or None,
        "bot_tag_matches": result.get("bot_tag_matches") or None,
        "classification_notes": result.get("classification_notes") or None,
        "whitelisted": bool(result.get("whitelisted")),
        "source": "central_otx",
        "checked_at": now.isoformat(),
    }

    asn = result.get("asn") or None

    with _db_lock:
        with connect_db(database_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO threat_intel (
                        ip, otx_pulse_count, reputation_score, tags,
                        malware_families, last_checked_at, raw_response
                    ) VALUES (
                        %s::inet, %s, %s, %s, NULL, %s, %s::jsonb
                    )
                    ON CONFLICT (ip) DO UPDATE SET
                        otx_pulse_count = EXCLUDED.otx_pulse_count,
                        reputation_score = EXCLUDED.reputation_score,
                        tags = EXCLUDED.tags,
                        last_checked_at = EXCLUDED.last_checked_at,
                        raw_response = EXCLUDED.raw_response
                    """,
                    (ip, pulse_count, reputation, tags, now, json.dumps(raw)),
                )
                if asn:
                    cur.execute(
                        "UPDATE ip_registry SET asn = COALESCE(asn, %s) WHERE ip = %s::inet",
                        (asn, ip),
                    )
            conn.commit()


def normalize_tag(tag: str) -> str:
    return re.sub(r"[\s_]+", "-", tag.strip().lower())


def tags_match_keywords(tags: list[str], keywords: set[str]) -> list[str]:
    matched = []
    for tag in tags:
        normalized = normalize_tag(tag)
        for keyword in keywords:
            if keyword in normalized or normalized in keyword:
                matched.append(tag)
                break
    return matched


def collect_pulse_tags(pulses: list[dict[str, Any]]) -> list[str]:
    tags: list[str] = []
    for pulse in pulses:
        tags.extend(pulse.get("tags") or [])
    return tags


def collect_pulse_names(pulses: list[dict[str, Any]]) -> list[str]:
    return [pulse.get("name", "") for pulse in pulses if pulse.get("name")]


def is_whitelisted(general_data: dict[str, Any]) -> bool:
    validation = general_data.get("validation") or []
    for item in validation:
        source = str(item.get("source", "")).lower()
        name = str(item.get("name", "")).lower()
        if "whitelist" in source or "whitelist" in name or "false positive" in name:
            return True
    return bool(general_data.get("false_positive"))


def fetch_otx_section(
    session: requests.Session,
    ip: str,
    section: str,
    timeout: float,
    max_retries: int = 6,
) -> tuple[dict[str, Any] | None, str | None]:
    url = f"{OTX_BASE_URL}/indicators/IPv4/{ip}/{section}"
    last_error = None

    for attempt in range(max_retries):
        try:
            response = session.get(url, timeout=timeout)
            if response.status_code == 429:
                wait = min(90, 5 * (2 ** attempt))
                with _print_lock:
                    print(f"  Rate limited on {ip}/{section}, waiting {wait}s...", flush=True)
                time.sleep(wait)
                continue
            if response.status_code == 404:
                return {}, None
            response.raise_for_status()
            return response.json(), None
        except requests.RequestException as exc:
            last_error = str(exc)
            wait = min(30, 2 ** attempt)
            with _print_lock:
                print(f"  Retry {attempt + 1}/{max_retries} for {ip}/{section}: {exc}", flush=True)
            time.sleep(wait)

    return None, last_error


def classify_from_otx(
    general_data: dict[str, Any] | None,
    malware_data: dict[str, Any] | None,
    csv_row: dict[str, Any],
) -> dict[str, Any]:
    if general_data is None:
        return {
            "malicious_status": "Error",
            "ip_type": "Unknown",
            "otx_reputation_score": None,
            "pulse_count": None,
            "malware_sample_count": None,
            "otx_tags": "",
            "pulse_names": "",
            "malicious_tag_matches": "",
            "bot_tag_matches": "",
            "asn": "",
            "otx_country": "",
            "whitelisted": False,
            "classification_notes": "OTX API request failed",
        }

    pulses = (general_data.get("pulse_info") or {}).get("pulses") or []
    pulse_count = (general_data.get("pulse_info") or {}).get("count", len(pulses))
    all_tags = collect_pulse_tags(pulses)
    pulse_names = collect_pulse_names(pulses)
    whitelisted = is_whitelisted(general_data)

    malware_count = 0
    if malware_data:
        malware_count = int(
            malware_data.get("count")
            or len(malware_data.get("data") or [])
            or 0
        )

    reputation_score = general_data.get("reputation")
    malicious_matches = tags_match_keywords(all_tags, MALICIOUS_TAG_KEYWORDS)
    bot_matches = tags_match_keywords(all_tags, BOT_TAG_KEYWORDS)

    attack_count = int(csv_row.get("attack_count") or 0)
    top_protocol = str(csv_row.get("top_protocol") or "").upper()
    asn = str(general_data.get("asn") or "")
    asn_lower = asn.lower()

    notes: list[str] = []

    if whitelisted:
        malicious_status = "Clean (Whitelisted)"
        notes.append("OTX marks this IP as whitelisted or known false positive")
    elif pulse_count > 0 and (malicious_matches or malware_count > 0):
        malicious_status = "Malicious"
        notes.append("Listed in OTX threat pulses and/or linked to malware")
    elif pulse_count > 0 and bot_matches:
        malicious_status = "Suspicious (Scanner/Bot)"
        notes.append("Listed in OTX scanner/automation feeds")
    elif pulse_count > 0:
        malicious_status = "Suspicious"
        notes.append("Present in OTX pulses without clear malicious tags")
    elif reputation_score not in (None, 0):
        malicious_status = "Malicious"
        notes.append(f"Non-zero OTX reputation score: {reputation_score}")
    else:
        malicious_status = "Clean"
        notes.append("No OTX threat pulses found")

    hosting_asn = any(keyword in asn_lower for keyword in HOSTING_ASN_KEYWORDS)
    scanner_protocol = top_protocol in {"SSH", "TCP"} and attack_count >= 500
    high_volume_attacker = attack_count >= 10000

    if bot_matches or scanner_protocol or high_volume_attacker:
        ip_type = "Bot/Scanner"
        if bot_matches:
            notes.append(f"OTX bot/scanner tags: {', '.join(bot_matches)}")
        if scanner_protocol:
            notes.append(f"High-volume {top_protocol} activity in your logs ({attack_count:,} events)")
        if high_volume_attacker and not scanner_protocol:
            notes.append(f"Very high attack volume in your logs ({attack_count:,} events)")
    elif hosting_asn and attack_count >= 100:
        ip_type = "Bot/Scanner (Hosting/Datacenter)"
        notes.append(f"Datacenter/hosting ASN with automated traffic pattern: {asn}")
    elif whitelisted:
        ip_type = "Infrastructure (Whitelisted)"
    elif top_protocol in {"HTTP", "HTTPS"} and attack_count <= 50 and pulse_count == 0:
        ip_type = "Likely Real User"
        notes.append("Low-volume web traffic with no OTX threat intelligence")
    elif pulse_count == 0 and attack_count <= 100:
        ip_type = "Likely Real User"
        notes.append("Low activity and no OTX threat intelligence")
    else:
        ip_type = "Uncertain"
        notes.append("Mixed signals; manual review recommended")

    return {
        "malicious_status": malicious_status,
        "ip_type": ip_type,
        "otx_reputation_score": reputation_score,
        "pulse_count": pulse_count,
        "malware_sample_count": malware_count,
        "otx_tags": ", ".join(sorted(set(all_tags))),
        "pulse_names": " | ".join(pulse_names[:5]),
        "malicious_tag_matches": ", ".join(malicious_matches),
        "bot_tag_matches": ", ".join(bot_matches),
        "asn": asn,
        "otx_country": general_data.get("country_name") or "",
        "whitelisted": whitelisted,
        "classification_notes": "; ".join(notes),
    }


def style_workbook(writer: pd.ExcelWriter, summary_df: pd.DataFrame) -> None:
    workbook = writer.book
    summary_sheet = writer.sheets["Summary"]
    summary_sheet.column_dimensions["A"].width = 28
    summary_sheet.column_dimensions["B"].width = 18

    data_sheets = [
        "All Results",
        "Malicious & Suspicious",
        "Clean IPs",
        "Bots & Scanners",
        "Likely Real Users",
    ]

    for sheet_name in writer.sheets:
        worksheet = writer.sheets[sheet_name]
        for column_cells in worksheet.columns:
            max_length = 0
            column_letter = column_cells[0].column_letter
            for cell in column_cells[:200]:
                value = "" if cell.value is None else str(cell.value)
                max_length = max(max_length, len(value))
            worksheet.column_dimensions[column_letter].width = min(max_length + 2, 60)

        if sheet_name in data_sheets and worksheet.max_row > 1:
            worksheet.freeze_panes = "A2"
            worksheet.auto_filter.ref = worksheet.dimensions


def build_summary(results_df: pd.DataFrame) -> pd.DataFrame:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    rows = [
        ("Generated At", generated_at),
        ("Total IPs Analyzed", len(results_df)),
        ("Malicious", int((results_df["malicious_status"] == "Malicious").sum())),
        ("Suspicious (Scanner/Bot)", int((results_df["malicious_status"] == "Suspicious (Scanner/Bot)").sum())),
        ("Suspicious", int((results_df["malicious_status"] == "Suspicious").sum())),
        ("Clean", int(results_df["malicious_status"].isin(["Clean", "Clean (Whitelisted)"]).sum())),
        ("Errors", int((results_df["malicious_status"] == "Error").sum())),
        ("Bot/Scanner", int(results_df["ip_type"].str.contains("Bot/Scanner", na=False).sum())),
        ("Likely Real User", int((results_df["ip_type"] == "Likely Real User").sum())),
        ("Uncertain", int((results_df["ip_type"] == "Uncertain").sum())),
    ]
    return pd.DataFrame(rows, columns=["Metric", "Value"])


def load_input_file(path: str) -> pd.DataFrame:
    suffix = Path(path).suffix.lower()
    if suffix == ".csv":
        return pd.read_csv(path)
    if suffix in {".xlsx", ".xls"}:
        return pd.read_excel(path)
    raise ValueError(f"Unsupported input format: {suffix}. Use .csv or .xlsx")


def load_checkpoint(path: str) -> pd.DataFrame:
    if not os.path.exists(path):
        return pd.DataFrame()
    return pd.read_csv(path)


def save_checkpoint(path: str, results_df: pd.DataFrame) -> None:
    results_df.to_csv(path, index=False)


def batch_excel_path(output_path: str, count: int) -> str:
    path = Path(output_path)
    return str(path.with_name(f"{path.stem}_at_{count}{path.suffix}"))


def batch_checkpoint_path(checkpoint_path: str, count: int) -> str:
    path = Path(checkpoint_path)
    return str(path.with_name(f"{path.stem}_at_{count}{path.suffix}"))


def maybe_write_batch_report(
    results_df: pd.DataFrame,
    count: int,
    output_path: str,
    checkpoint_path: str,
    batch_size: int,
) -> None:
    if batch_size <= 0 or count % batch_size != 0:
        return

    batch_csv = batch_checkpoint_path(checkpoint_path, count)
    batch_xlsx = batch_excel_path(output_path, count)
    save_checkpoint(batch_csv, results_df)
    write_excel_report(results_df, batch_xlsx)
    write_excel_report(results_df, output_path)
    print(
        f"\n>>> Batch checkpoint at {count} IPs:"
        f"\n    CSV  : {batch_csv}"
        f"\n    CSV  : {checkpoint_path} (latest)"
        f"\n    Excel: {batch_xlsx}"
        f"\n    Excel: {output_path} (latest)\n",
        flush=True,
    )


def write_excel_report(results_df: pd.DataFrame, output_path: str) -> pd.DataFrame:
    summary_df = build_summary(results_df)

    malicious_df = results_df[
        results_df["malicious_status"].isin(
            ["Malicious", "Suspicious (Scanner/Bot)", "Suspicious"]
        )
    ].copy()
    clean_df = results_df[
        results_df["malicious_status"].isin(["Clean", "Clean (Whitelisted)"])
    ].copy()
    bots_df = results_df[
        results_df["ip_type"].str.contains("Bot/Scanner", na=False)
    ].copy()
    real_df = results_df[results_df["ip_type"] == "Likely Real User"].copy()

    with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
        summary_df.to_excel(writer, sheet_name="Summary", index=False)
        results_df.to_excel(writer, sheet_name="All Results", index=False)
        malicious_df.to_excel(writer, sheet_name="Malicious & Suspicious", index=False)
        clean_df.to_excel(writer, sheet_name="Clean IPs", index=False)
        bots_df.to_excel(writer, sheet_name="Bots & Scanners", index=False)
        real_df.to_excel(writer, sheet_name="Likely Real Users", index=False)
        style_workbook(writer, summary_df)

    return summary_df


def acquire_run_lock(lock_path: Path) -> None:
    if lock_path.exists():
        try:
            lock_age = time.time() - lock_path.stat().st_mtime
        except OSError:
            lock_age = 0
        if lock_age < 6 * 3600:
            print(
                f"Error: Another run may already be active ({lock_path}).\n"
                "Delete that file only if no other checker process is running.",
                file=sys.stderr,
            )
            raise SystemExit(1)

    lock_path.write_text(
        json.dumps(
            {
                "pid": os.getpid(),
                "started_at": datetime.now(timezone.utc).isoformat(),
            }
        ),
        encoding="utf-8",
    )


def release_run_lock(lock_path: Path) -> None:
    try:
        lock_path.unlink(missing_ok=True)
    except OSError:
        pass


def build_results_dataframe(
    input_df: pd.DataFrame,
    results_by_ip: dict[str, dict[str, Any]],
) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for _, row in input_df.iterrows():
        ip = str(row["source_ip"]).strip()
        if ip in results_by_ip:
            rows.append(results_by_ip[ip])
    return pd.DataFrame(rows)


def check_single_ip(
    row_dict: dict[str, Any],
    api_key: str,
    timeout: float,
    fetch_malware: bool,
    delay: float,
) -> dict[str, Any]:
    session = requests.Session()
    session.headers.update(
        {
            "X-OTX-API-KEY": api_key,
            "Accept": "application/json",
            "User-Agent": "AlienVault-IP-Checker/1.0",
        }
    )

    ip = str(row_dict["source_ip"]).strip()
    general_data, general_error = fetch_otx_section(session, ip, "general", timeout)
    if delay > 0:
        time.sleep(delay)

    malware_data = None
    if fetch_malware and general_data is not None:
        malware_data, _ = fetch_otx_section(session, ip, "malware", timeout)
        if delay > 0:
            time.sleep(delay)

    classification = classify_from_otx(general_data, malware_data, row_dict)
    if general_error:
        classification["malicious_status"] = "Error"
        classification["classification_notes"] = general_error

    result_row = row_dict.copy()
    result_row.update(classification)
    return result_row


def process_ips_parallel(
    input_df: pd.DataFrame,
    pending_rows: list[pd.Series],
    results_by_ip: dict[str, dict[str, Any]],
    args: argparse.Namespace,
    total: int,
    database_url: str | None = None,
) -> pd.DataFrame:
    results_lock = threading.Lock()
    last_batch_count = len(results_by_ip)

    def handle_result(ip: str, result_row: dict[str, Any]) -> pd.DataFrame:
        nonlocal last_batch_count
        if database_url:
            try:
                upsert_threat_intel_row(database_url, result_row)
            except Exception as exc:  # noqa: BLE001
                with _print_lock:
                    print(f"  DB upsert failed for {ip}: {exc}", flush=True)

        with results_lock:
            results_by_ip[ip] = result_row
            results_df = build_results_dataframe(input_df, results_by_ip)
            count = len(results_df)
            save_checkpoint(args.checkpoint, results_df)

            if count != last_batch_count and count % 25 == 0:
                with _print_lock:
                    mal = sum(
                        1
                        for r in results_by_ip.values()
                        if str(r.get("malicious_status", "")).startswith("Malicious")
                        or "Suspicious" in str(r.get("malicious_status", ""))
                    )
                    print(
                        f"[{count}/{total}] progress... ({mal} malicious/suspicious so far)",
                        flush=True,
                    )

            if count > last_batch_count and count % args.batch_size == 0:
                maybe_write_batch_report(
                    results_df,
                    count,
                    args.output,
                    args.checkpoint,
                    args.batch_size,
                )
                last_batch_count = count

            with _print_lock:
                status = result_row.get("malicious_status", "?")
                print(f"[{count}/{total}] {ip} → {status}", flush=True)

            return results_df

    results_df = build_results_dataframe(input_df, results_by_ip)
    pending_by_ip = {str(row["source_ip"]).strip(): row.to_dict() for row in pending_rows}

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_ip = {
            executor.submit(
                check_single_ip,
                row.to_dict(),
                args.api_key,
                args.timeout,
                args.fetch_malware,
                args.delay,
            ): str(row["source_ip"]).strip()
            for row in pending_rows
        }

        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                result_row = future.result()
            except Exception as exc:
                pending_row = pending_by_ip.get(ip, {"source_ip": ip})
                result_row = pending_row.copy()
                error_fields = classify_from_otx(None, None, pending_row)
                error_fields["malicious_status"] = "Error"
                error_fields["classification_notes"] = str(exc)
                result_row.update(error_fields)
            results_df = handle_result(ip, result_row)

    return results_df


def run_wave(
    input_df: pd.DataFrame,
    args: argparse.Namespace,
    database_url: str | None,
    results_by_ip: dict[str, dict[str, Any]],
) -> pd.DataFrame:
    pending_rows = [
        row
        for _, row in input_df.iterrows()
        if str(row["source_ip"]).strip() not in results_by_ip
    ]
    total = len(input_df)
    if not pending_rows:
        return build_results_dataframe(input_df, results_by_ip)

    print(
        f"Checking {len(pending_rows)} IPs via AlienVault OTX "
        f"({len(results_by_ip)} already done) with {args.workers} threads...",
        flush=True,
    )
    return process_ips_parallel(
        input_df,
        pending_rows,
        results_by_ip,
        args,
        total,
        database_url=database_url,
    )


def main() -> int:
    args = parse_args()
    if not args.api_key:
        print(
            "Error: OTX API key required. Set OTX_API_KEY or pass --api-key.",
            file=sys.stderr,
        )
        return 1

    database_url = args.database_url if args.from_db or args.watch else None
    if args.from_db or args.watch:
        if not database_url:
            print("Error: --database-url / DATABASE_URL required for --from-db/--watch", file=sys.stderr)
            return 1
        # Strip SQLAlchemy driver suffix if present
        database_url = dsn_from_url(database_url)

    Path(args.checkpoint).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)

    lock_path = Path(args.checkpoint).with_suffix(".lock")
    acquire_run_lock(lock_path)
    atexit.register(release_run_lock, lock_path)

    results_by_ip: dict[str, dict[str, Any]] = {}
    if args.resume and os.path.exists(args.checkpoint):
        checkpoint_df = load_checkpoint(args.checkpoint)
        if not checkpoint_df.empty and "source_ip" in checkpoint_df.columns:
            for _, row in checkpoint_df.iterrows():
                ip = str(row["source_ip"]).strip()
                results_by_ip[ip] = row.to_dict()
            print(f"Resuming: {len(results_by_ip)} IPs already in checkpoint.", flush=True)

    # ── One-shot / initial backfill ──────────────────────────────────────────
    if args.from_db:
        print("Loading pending IPs from Postgres ip_registry...", flush=True)
        input_df = load_pending_ips_from_db(database_url, limit=args.limit)
        if input_df.empty:
            print("No unchecked IPs found.", flush=True)
        else:
            print(f"Loaded {len(input_df)} pending IPs from DB.", flush=True)
            try:
                results_df = run_wave(input_df, args, database_url, results_by_ip)
            except KeyboardInterrupt:
                print("\nInterrupted. Progress saved.", flush=True)
                results_df = build_results_dataframe(input_df, results_by_ip)
                if not results_df.empty:
                    save_checkpoint(args.checkpoint, results_df)
                    write_excel_report(results_df, args.output)
                return 130
            if not results_df.empty:
                save_checkpoint(args.checkpoint, results_df)
                summary_df = write_excel_report(results_df, args.output)
                print(f"\nBackfill wave done. Excel: {args.output}", flush=True)
                print(summary_df.to_string(index=False), flush=True)
    elif args.input:
        if not os.path.exists(args.input):
            print(f"Error: Input file not found: {args.input}", file=sys.stderr)
            return 1
        input_df = load_input_file(args.input)
        if "source_ip" not in input_df.columns:
            print("Error: Input file must contain a 'source_ip' column.", file=sys.stderr)
            return 1
        if args.limit > 0:
            input_df = input_df.head(args.limit)
        results_df = run_wave(input_df, args, database_url, results_by_ip)
        if not results_df.empty:
            write_excel_report(results_df, args.output)
    elif not args.watch:
        print("Error: pass --from-db or --input <file>", file=sys.stderr)
        return 1

    # ── Continuous: poll for newly seen IPs ──────────────────────────────────
    if args.watch:
        print(
            f"\n[watch] continuous mode on — polling every {args.watch_interval}s "
            f"for new unchecked IPs (chunk={args.chunk_size}, workers={args.workers})",
            flush=True,
        )
        while True:
            try:
                wave_df = load_pending_ips_from_db(database_url, limit=args.chunk_size)
                if wave_df.empty:
                    time.sleep(args.watch_interval)
                    continue
                # Fresh results map for this wave (already-written IPs won't appear)
                wave_results: dict[str, dict[str, Any]] = {}
                print(f"[watch] {len(wave_df)} new/pending IPs — checking...", flush=True)
                results_df = run_wave(wave_df, args, database_url, wave_results)
                if not results_df.empty:
                    # Append to cumulative checkpoint
                    try:
                        prev = load_checkpoint(args.checkpoint)
                        combined = pd.concat([prev, results_df], ignore_index=True)
                        if "source_ip" in combined.columns:
                            combined = combined.drop_duplicates(subset=["source_ip"], keep="last")
                        save_checkpoint(args.checkpoint, combined)
                    except Exception:
                        save_checkpoint(args.checkpoint, results_df)
                time.sleep(2.0)
            except KeyboardInterrupt:
                print("\n[watch] stopped.", flush=True)
                return 0
            except Exception as exc:  # noqa: BLE001
                print(f"[watch] cycle error: {exc!r}", flush=True)
                time.sleep(args.watch_interval)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
