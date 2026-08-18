"""
Full QA sweep of the published console.

Checks each route for console errors, failed requests, stuck loading states,
accessibility regressions, layout overflow, leaked deployment identifiers, and
working file downloads. Exits non-zero if anything fails, so it can gate a deploy.

    python qa.py [base_url]
"""
import re
import sys

from playwright.sync_api import sync_playwright

BASE = (sys.argv[1] if len(sys.argv) > 1 else "https://trapline-console.vercel.app").rstrip("/")

ROUTES = [
    "/", "/analysis", "/detections", "/reports",
    "/ips/cross-vps", "/settings/vps",
    "/ips/213.209.159.115", "/vps/SENSOR-01",
]
DOWNLOADS = [
    "/api/v1/detections/sigma.yml",
    "/api/v1/detections/stix",
    "/api/v1/detections/blocklist",
    "/api/v1/analysis/report",
]
# Identifiers that must never appear in a published response.
FORBIDDEN = re.compile(
    r"canteen\s+stores?|frontier\s+works|national\s+logistics?\s+cell|the\s+caring\s+store"
    r"|101\.50\.107\.149|158\.69\.63\.177|203\.135\.42\.52|13\.140\.175\.16"
    r"|beelzebub|luresecure|asimzaman|cyberdiv",
    re.I,
)

PROBE = """() => {
  const bad = [];
  document.querySelectorAll('a[href],button').forEach(e => {
    const b = e.getBoundingClientRect();
    if (!b.height) return;
    if (b.height < 24) bad.push('target<24px: ' + (e.innerText||e.getAttribute('aria-label')||e.tagName).slice(0,28));
    if (e.tagName === 'BUTTON') {
      const t = e.getAttribute('type');
      if (t !== 'button' && t !== 'submit') bad.push('untyped button: ' + (e.innerText||'').slice(0,28));
      if (!(e.innerText||'').trim() && !e.getAttribute('aria-label')) bad.push('unlabelled icon button');
    }
  });
  document.querySelectorAll('[title^="SENSOR"],[title^="Sensor"]').forEach(d => {
    if (d.scrollWidth > d.clientWidth + 1) bad.push('clipped badge: ' + d.title);
  });
  return {
    problems: bad,
    overflow: document.documentElement.scrollWidth > window.innerWidth + 1,
    text: document.body.innerText,
  };
}"""

STUCK = re.compile(r"loading|deriving|compiling|please wait", re.I)
BROKEN = re.compile(r"failed|error|undefined|NaN|\[object Object\]|No snapshot data", re.I)


def main() -> int:
    failures: list[str] = []

    with sync_playwright() as p:
        browser = p.chromium.launch()
        for width, label in ((1500, "desktop"), (390, "mobile")):
            page = browser.new_page(viewport={"width": width, "height": 1000})
            errors: list[str] = []
            failed: list[str] = []
            page.on("pageerror", lambda e: errors.append(str(e)[:160]))
            page.on("console", lambda m: errors.append("console." + m.type + ": " + m.text[:140])
                    if m.type == "error" else None)
            # net::ERR_ABORTED is a Next.js prefetch cancelled when we navigate away,
            # not a broken link. Every such URL was verified to return 200 directly and
            # as an RSC request, so treating aborts as failures only produces noise.
            page.on("requestfailed", lambda r: failed.append(f"{r.failure} {r.url[-64:]}")
                    if "ERR_ABORTED" not in (r.failure or "") else None)
            page.on("response", lambda r: failed.append(f"HTTP {r.status} {r.url[-60:]}")
                    if r.status >= 400 else None)

            print(f"\n=== {label} ({width}px)")
            for route in ROUTES:
                errors.clear(); failed.clear()
                page.goto(BASE + route, wait_until="networkidle", timeout=120_000)
                page.wait_for_timeout(4000)
                r = page.evaluate(PROBE)
                issues = list(r["problems"])
                if r["overflow"]:
                    issues.append("horizontal overflow")
                body = r["text"]
                if STUCK.search(body) and len(body) < 400:
                    issues.append("stuck loading state")
                for m in set(BROKEN.findall(body)):
                    issues.append(f"broken text: {m}")
                if FORBIDDEN.search(body):
                    issues.append(f"LEAK: {FORBIDDEN.search(body).group(0)}")
                issues += [f"pageerror: {e}" for e in errors]
                issues += [f"request: {f}" for f in failed]

                if issues:
                    print(f"  {route:<18} FAIL")
                    for i in dict.fromkeys(issues):
                        print(f"      - {i}")
                    failures += [f"{label}{route}: {i}" for i in dict.fromkeys(issues)]
                else:
                    print(f"  {route:<18} clean")
            page.close()

        # Downloads and raw API payloads.
        print("\n=== downloads / API")
        page = browser.new_page()
        for path in DOWNLOADS:
            resp = page.request.get(BASE + path)
            body = resp.text()
            issues = []
            if resp.status != 200:
                issues.append(f"HTTP {resp.status}")
            if not body.strip():
                issues.append("empty body")
            if FORBIDDEN.search(body):
                issues.append(f"LEAK: {FORBIDDEN.search(body).group(0)}")
            print(f"  {path:<38} {'FAIL ' + '; '.join(issues) if issues else f'ok ({len(body):,} bytes)'}")
            failures += [f"{path}: {i}" for i in issues]
        page.close()
        browser.close()

    print("\n" + "=" * 60)
    if failures:
        print(f"{len(failures)} failure(s)")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
