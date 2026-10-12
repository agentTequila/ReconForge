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
