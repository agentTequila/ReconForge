"""VirusTotal v3 client (domain + IP reputation)."""

from __future__ import annotations

from typing import Any

import requests

from reconforge.integrations import IntegrationError

BASE = "https://www.virustotal.com/api/v3"


def _get(path: str, key: str, session: requests.Session | None) -> dict[str, Any]:
    sess = session or requests.Session()
    resp = sess.get(f"{BASE}{path}", headers={"x-apikey": key}, timeout=30)
    if resp.status_code == 404:
        return {"found": False}
    if resp.status_code != 200:
        raise IntegrationError(f"VirusTotal lookup failed (HTTP {resp.status_code})")
    return resp.json().get("data", {})


def domain_reputation(domain: str, key: str,
                      session: requests.Session | None = None) -> dict[str, Any]:
    data = _get(f"/domains/{domain}", key, session)
    if not data.get("found", True):
        return {"domain": domain, "found": False}
    attrs = data.get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "domain": domain,
        "found": True,
        "reputation": attrs.get("reputation"),
        "last_analysis_stats": stats,
        "categories": attrs.get("categories", {}),
        "total_votes": attrs.get("total_votes", {}),
    }


def ip_reputation(ip: str, key: str, session: requests.Session | None = None) -> dict[str, Any]:
    data = _get(f"/ip_addresses/{ip}", key, session)
    if not data.get("found", True):
        return {"ip": ip, "found": False}
    attrs = data.get("attributes", {})
    return {
        "ip": ip,
        "found": True,
        "reputation": attrs.get("reputation"),
        "last_analysis_stats": attrs.get("last_analysis_stats", {}),
        "as_owner": attrs.get("as_owner"),
    }
