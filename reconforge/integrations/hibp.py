"""Have I Been Pwned client (breached accounts + k-anonymity password range)."""

from __future__ import annotations

from typing import Any

import requests

from reconforge.integrations import IntegrationError

BASE = "https://haveibeenpwned.com/api/v3"
UA = "ReconForge-OSINT"


def breached_account(email: str, key: str,
                     session: requests.Session | None = None) -> dict[str, Any]:
    sess = session or requests.Session()
    resp = sess.get(
        f"{BASE}/breachedaccount/{email}",
        params={"truncateResponse": "false"},
        headers={"hibp-api-key": key, "User-Agent": UA},
        timeout=30,
    )
    if resp.status_code == 404:
        return {"email": email, "breach_count": 0, "breaches": []}
    if resp.status_code != 200:
        raise IntegrationError(f"HIBP lookup failed (HTTP {resp.status_code})")
    breaches = resp.json()
    return {
        "email": email,
        "breach_count": len(breaches),
        "breaches": [
            {
                "name": b.get("Name"),
                "title": b.get("Title"),
                "domain": b.get("Domain"),
                "breach_date": b.get("BreachDate"),
                "pwn_count": b.get("PwnCount"),
                "data_classes": b.get("DataClasses", []),
            }
            for b in breaches
        ],
    }


def password_range(password: str, session: requests.Session | None = None) -> dict[str, Any]:
    """k-anonymity range lookup - no API key, password never leaves the machine."""
    import hashlib

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    sess = session or requests.Session()
    resp = sess.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=30)
    if resp.status_code != 200:
        raise IntegrationError(f"HIBP password range failed (HTTP {resp.status_code})")
    count = 0
    for line in resp.text.splitlines():
        parts = line.split(":")
        if len(parts) == 2 and parts[0] == suffix:
            count = int(parts[1].strip())
            break
    return {"sha1_prefix": prefix, "occurrences": count, "pwned": count > 0}
