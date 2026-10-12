"""Shodan REST client (host info + domain search)."""

from __future__ import annotations

from typing import Any

import requests

from reconforge.integrations import IntegrationError

BASE = "https://api.shodan.io"


def host_info(ip: str, key: str, session: requests.Session | None = None) -> dict[str, Any]:
    sess = session or requests.Session()
    resp = sess.get(f"{BASE}/shodan/host/{ip}", params={"key": key}, timeout=30)
    if resp.status_code == 404:
        return {"ip": ip, "found": False}
    if resp.status_code != 200:
        raise IntegrationError(f"Shodan host lookup failed (HTTP {resp.status_code})")
    data = resp.json()
    services = [
        {
            "port": item.get("port"),
            "transport": item.get("transport"),
            "product": item.get("product"),
            "version": item.get("version"),
            "banner": (item.get("data") or "")[:300],
        }
        for item in data.get("data", [])
    ]
    return {
        "ip": ip,
        "found": True,
        "org": data.get("org"),
        "isp": data.get("isp"),
        "asn": data.get("asn"),
        "os": data.get("os"),
        "ports": data.get("ports", []),
        "vulns": list(data.get("vulns", []) or []),
        "tags": data.get("tags", []),
        "hostnames": data.get("hostnames", []),
        "services": services,
    }


def domain_info(domain: str, key: str, session: requests.Session | None = None) -> dict[str, Any]:
    sess = session or requests.Session()
    resp = sess.get(
        f"{BASE}/dns/domain/{domain}", params={"key": key}, timeout=30
    )
    if resp.status_code == 404:
        return {"domain": domain, "found": False}
    if resp.status_code != 200:
        raise IntegrationError(f"Shodan domain lookup failed (HTTP {resp.status_code})")
    data = resp.json()
    return {
        "domain": domain,
        "found": True,
        "subdomains": data.get("subdomains", []),
        "values": data.get("values", []),
    }
