"""IP address reconnaissance modules."""

from __future__ import annotations

import socket

from reconforge.core.context import ScanContext
from reconforge.core.registry import register_module
from reconforge.core.target import Target
from reconforge.integrations import shodan_api, virustotal

LINKS = {
    "AbuseIPDB": "https://www.abuseipdb.com/check/{ip}",
    "Shodan": "https://www.shodan.io/host/{ip}",
    "VirusTotal": "https://www.virustotal.com/gui/ip-address/{ip}",
    "urlscan.io": "https://urlscan.io/search/#ip:{ip}",
    "Censys": "https://search.censys.io/hosts/{ip}",
    "GreyNoise": "https://viz.greynoise.io/ip/{ip}",
    "Robtex": "https://www.robtex.com/ip/{ip}",
    "BGPView": "https://bgpview.io/ip/{ip}",
    "IntelX": "https://intelx.io/?s={ip}",
    "DNSlytics": "https://dnslytics.com/ip/{ip}",
}


@register_module(
    id="ip.rdap",
    target_kinds=["ip"],
    profile="passive",
    description="RDAP registration data (network range, org, abuse contact)",
)
def rdap_lookup(target: Target, ctx: ScanContext):
    resp = ctx.http("GET", f"https://rdap.org/ip/{target.value}", timeout=30)
    if resp.status_code != 200:
        return {"found": False, "http_status": resp.status_code}, []
    data = resp.json()
    remarks = [
        r.get("description", "")
        for r in data.get("remarks", [])
        if isinstance(r.get("description"), list)
    ]
    entities = []
    for ent in data.get("entities", []):
        roles = ent.get("roles", [])
        handle = ent.get("handle")
        vcard = ent.get("vcardArray")
        email = None
        if vcard and len(vcard) > 1:
            for item in vcard[1]:
                if item and item[0] == "email":
                    email = item[3]
        entities.append({"handle": handle, "roles": roles, "email": email})
    abuse = next(
        (e["email"] for e in entities
         if e.get("email") and "abuse" in (e.get("roles") or [])),
        None,
    )
    findings = []
    if abuse:
        findings.append(f"Abuse contact: {abuse}")
    return {
        "found": True,
        "name": data.get("name"),
        "handle": data.get("handle"),
        "start_address": data.get("startAddress"),
        "end_address": data.get("endAddress"),
        "country": data.get("country"),
        "entities": entities,
        "abuse_email": abuse,
        "remarks": remarks,
    }, findings


@register_module(
    id="ip.geo",
    target_kinds=["ip"],
    profile="passive",
    description="Geolocation / ASN / org via ip-api.com",
)
def geo_lookup(target: Target, ctx: ScanContext):
    fields = "status,message,country,regionName,city,lat,lon,isp,org,as,mobile,proxy,hosting"
    resp = ctx.http(
        "GET", f"http://ip-api.com/json/{target.value}",
        params={"fields": fields}, timeout=15,
    )
    data = resp.json()
    if data.get("status") != "success":
        return {"found": False, "message": data.get("message")}, []
    findings = []
    if data.get("proxy"):
        findings.append("IP is known to be a proxy/VPN exit")
    if data.get("hosting"):
        findings.append("IP belongs to a hosting/datacenter provider")
    return {"found": True, **{k: v for k, v in data.items() if k != "status"}}, findings


@register_module(
    id="ip.rdns",
    target_kinds=["ip"],
    profile="passive",
    description="Reverse DNS lookup",
)
def reverse_dns(target: Target, ctx: ScanContext):
    try:
        host, aliases, _ = socket.gethostbyaddr(target.value)
    except OSError:
        return {"hostname": None, "aliases": []}, []
    findings = [f"rDNS hostname: {host}"] if host else []
    return {"hostname": host, "aliases": list(aliases)}, findings


@register_module(
    id="ip.shodan",
    target_kinds=["ip"],
    profile="passive",
    requires_keys=["SHODAN_API_KEY"],
    description="Shodan exposed services, ports and CVEs for the IP",
)
def shodan_lookup(target: Target, ctx: ScanContext):
    data = shodan_api.host_info(target.value, ctx.keys["SHODAN_API_KEY"], ctx.session)
    findings = []
    if data.get("vulns"):
        findings.append(f"Known vulns: {', '.join(data['vulns'][:5])}")
    if data.get("ports"):
        findings.append(f"Open ports: {', '.join(map(str, data['ports'][:15]))}")
    return data, findings


@register_module(
    id="ip.virustotal",
    target_kinds=["ip"],
    profile="passive",
    requires_keys=["VIRUSTOTAL_API_KEY"],
    description="VirusTotal IP reputation",
)
def virustotal_lookup(target: Target, ctx: ScanContext):
    data = virustotal.ip_reputation(target.value, ctx.keys["VIRUSTOTAL_API_KEY"],
                                    ctx.session)
    findings = []
    stats = data.get("last_analysis_stats") or {}
    if stats.get("malicious", 0) > 0:
        findings.append(f"IP flagged malicious by {stats['malicious']} vendors")
    return data, findings


@register_module(
    id="ip.osint_links",
    target_kinds=["ip"],
    profile="passive",
    description="Threat-intel lookup URLs for the IP",
)
def ip_links(target: Target, ctx: ScanContext):
    return {"links": {name: tpl.format(ip=target.value) for name, tpl in LINKS.items()}}, []


def parse_nmap_output(text: str) -> list[dict]:
    """Parse ``nmap -sV`` normal-output lines into service records."""
    import re

    services: list[dict] = []
    for line in text.splitlines():
        match = re.match(
            r"^(\d+)/(tcp|udp)\s+(open\S*)\s+(\S+)\s*(.*)$", line.strip()
        )
        if match:
            services.append({
                "port": int(match.group(1)),
                "proto": match.group(2),
                "state": match.group(3),
                "service": match.group(4),
                "version": (match.group(5) or "").strip(),
            })
    return services


RISKY_SERVICE_HINTS = {
    21: "FTP - use SFTP/SCP instead",
    22: "SSH - ensure key-only auth and no root password logins",
    23: "Telnet - plaintext protocol, replace with SSH",
    3389: "RDP - brute-force surface, restrict behind VPN",
    445: "SMB - frequent ransomware entry point",
    1433: "MSSQL - verify it is not internet-exposed",
    3306: "MySQL - verify it is not internet-exposed",
    5432: "PostgreSQL - verify it is not internet-exposed",
    5900: "VNC - ensure strong auth or bind to localhost",
    6379: "Redis - unauthenticated Redis is a classic compromise vector",
    9200: "Elasticsearch - verify auth is enabled",
    27017: "MongoDB - unauthenticated MongoDB is a classic compromise vector",
}


@register_module(
    id="ip.nmap",
    target_kinds=["ip", "domain"],
    profile="active",
    description="Nmap service/version detection on top ports (requires nmap installed)",
)
def nmap_scan(target: Target, ctx: ScanContext):
    import shutil
    import subprocess

    from reconforge.core.engine import skip

    if not shutil.which("nmap"):
        skip("nmap binary not found - install Nmap (https://nmap.org) and retry")

    cmd = [
        "nmap", "-Pn", "-sV", "--top-ports", "100", "-T4", "--max-retries", "1",
        "-oN", "-", target.value,
    ]
    ctx.log(f"running: {' '.join(cmd)}")
    proc = subprocess.run(
        cmd, capture_output=True, text=True,
        timeout=min(ctx.module_timeout, 300), errors="replace",
    )
    services = parse_nmap_output(proc.stdout)
    risky = [
        {"port": s["port"], "note": RISKY_SERVICE_HINTS[s["port"]]}
        for s in services if s["port"] in RISKY_SERVICE_HINTS
    ]
    findings = []
    if services:
        findings.append(
            f"nmap: {len(services)} open port(s) with service details"
        )
    for item in risky:
        findings.append(f"Port {item['port']}: {item['note']}")
    return {
        "target": target.value,
        "open_services": services,
        "risky": risky,
        "exit_code": proc.returncode,
    }, findings


@register_module(
    id="ip.bgp",
    target_kinds=["ip"],
    profile="passive",
    description="BGP announcements for the IP (ASN, prefix, owning organization)",
)
def bgp_lookup(target: Target, ctx: ScanContext):
    resp = ctx.http("GET", f"https://api.bgpview.io/ip/{target.value}", timeout=20)
    if resp.status_code != 200:
        return {"found": False, "http_status": resp.status_code}, []
    payload = resp.json().get("data", {})
    asns = payload.get("asns", [])
    prefixes = payload.get("prefixes", [])
    first = asns[0] if asns else {}
    result = {
        "asn": first.get("asn"),
        "name": first.get("name"),
        "description": first.get("description"),
        "country_code": first.get("country_code"),
        "prefixes": [
            {"prefix": p.get("prefix"), "asn": p.get("asn")}
            for p in prefixes[:10]
        ],
    }
    findings = []
    if first.get("description"):
        findings.append(
            f"IP announced by AS{first.get('asn')} "
            f"({first.get('description')})"
        )
    return result, findings
