"""Hunter.io domain email search client."""

from __future__ import annotations

from typing import Any

import requests

from reconforge.integrations import IntegrationError

BASE = "https://api.hunter.io/v2"


def domain_search(domain: str, key: str,
                  session: requests.Session | None = None) -> dict[str, Any]:
    sess = session or requests.Session()
    resp = sess.get(
        f"{BASE}/domain-search",
        params={"domain": domain, "api_key": key, "limit": 100},
        timeout=30,
    )
    if resp.status_code != 200:
        raise IntegrationError(f"Hunter.io lookup failed (HTTP {resp.status_code})")
    payload = resp.json().get("data", {})
    emails = payload.get("emails", [])
    return {
        "domain": domain,
        "organization": payload.get("organization"),
        "pattern": payload.get("pattern"),
        "emails": [
            {
                "value": e.get("value"),
                "type": e.get("type"),
                "confidence": e.get("confidence"),
                "first_seen": e.get("first_seen"),
                "last_seen": e.get("last_seen"),
            }
            for e in emails
        ],
    }
