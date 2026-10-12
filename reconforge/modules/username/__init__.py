"""Username reconnaissance: cross-platform account checks + link fallbacks."""

from __future__ import annotations

import json
from pathlib import Path

import requests

from reconforge.core.context import ScanContext
from reconforge.core.registry import register_module
from reconforge.core.target import Target

DATA_FILE = Path(__file__).resolve().parents[2] / "data" / "platforms.json"


def load_platforms() -> list[dict]:
    with DATA_FILE.open(encoding="utf-8") as fh:
        return json.load(fh)["platforms"]


def _check_one(platform: dict, username: str, session: requests.Session,
               limiter) -> dict:
    url = platform["url"].replace("{username}", username)
    limiter.acquire()
    try:
        resp = session.get(url, timeout=10, allow_redirects=True)
    except requests.RequestException as exc:
        return {"platform": platform["name"], "status": "error", "url": url,
                "detail": str(exc)[:120]}

    code = resp.status_code
    body = resp.text
    body_marker = platform.get("body_marker")
    not_found_marker = platform.get("not_found_marker")
    marker_missing = bool(body_marker) and body_marker not in body
    soft_404 = bool(not_found_marker) and not_found_marker in body
    not_found_codes = set(platform.get("not_found_codes", [404]))

    if code in not_found_codes or marker_missing or soft_404:
        status = "not_found"
    elif code in (200, 403, 429):
        status = "likely_found" if code == 200 else "possible"
    else:
        status = "unknown"
    return {"platform": platform["name"], "status": status, "url": url,
            "http_status": code}


@register_module(
    id="username.platforms",
    target_kinds=["username"],
    profile="passive",
    description="Account existence checks across 60+ popular platforms",
)
def platform_checks(target: Target, ctx: ScanContext):
    platforms = load_platforms()
    session = requests.Session()
    session.headers.update({"User-Agent": ctx.session.headers["User-Agent"]})
    if ctx.proxy:
        session.proxies = {"http": ctx.proxy, "https": ctx.proxy}

    results: list[dict] = []

    def worker(platform: dict) -> None:
        entry = _check_one(platform, target.value, session, ctx.limiter)
        results.append(entry)
        if entry["status"] in ("likely_found", "possible"):
            ctx.log(f"{entry['platform']}: {entry['status']}", "success")

    from reconforge.modules.common import chunked_map

    chunked_map(worker, platforms, max_workers=15)

    found = [r for r in results if r["status"] == "likely_found"]
    possible = [r for r in results if r["status"] == "possible"]
    unknown = [r for r in results if r["status"] == "unknown"]
    findings = []
    if found:
        findings.append(
            f"Username active on {len(found)} platforms: "
            + ", ".join(r["platform"] for r in found[:8])
        )
    if unknown:
        findings.append(f"{len(unknown)} platforms need manual verification (bot walls)")
    results.sort(key=lambda r: (r["status"] != "likely_found", r["platform"]))
    return {"checked": len(platforms), "found": found, "possible": possible,
            "unknown": unknown, "not_found_count": sum(
                1 for r in results if r["status"] == "not_found"),
            "results": results}, findings
