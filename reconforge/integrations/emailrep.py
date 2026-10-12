"""EmailRep.io reputation client."""

from __future__ import annotations

from typing import Any

import requests

from reconforge.integrations import IntegrationError


def reputation(email: str, key: str,
               session: requests.Session | None = None) -> dict[str, Any]:
    sess = session or requests.Session()
    resp = sess.get(
        f"https://emailrep.io/{email}",
        headers={"Key": key, "User-Agent": "ReconForge-OSINT"},
        timeout=30,
    )
    if resp.status_code == 404:
        return {"email": email, "found": False}
    if resp.status_code != 200:
        raise IntegrationError(f"EmailRep lookup failed (HTTP {resp.status_code})")
    data = resp.json()
    return {
        "email": email,
        "found": True,
        "reputation": data.get("reputation"),
        "suspicious": data.get("suspicious"),
        "references": data.get("references"),
        "details": data.get("details", {}),
    }
