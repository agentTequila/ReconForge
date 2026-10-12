"""NumVerify (apilayer) phone validation client."""

from __future__ import annotations

from typing import Any

import requests

from reconforge.integrations import IntegrationError


def validate(number: str, key: str,
             session: requests.Session | None = None) -> dict[str, Any]:
    sess = session or requests.Session()
    resp = sess.get(
        "https://apilayer.net/api/validate",
        params={"access_key": key, "number": number},
        timeout=30,
    )
    if resp.status_code != 200:
        raise IntegrationError(f"NumVerify lookup failed (HTTP {resp.status_code})")
    data = resp.json()
    if not data.get("valid"):
        return {"number": number, "valid": False}
    return {
        "number": number,
        "valid": True,
        "local_format": data.get("local_format"),
        "international_format": data.get("international_format"),
        "country_name": data.get("country_name"),
        "country_code": data.get("country_code"),
        "location": data.get("location"),
        "carrier": data.get("carrier"),
        "line_type": data.get("line_type"),
    }
