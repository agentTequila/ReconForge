"""Passive domain reconnaissance modules."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

import dns.resolver

from reconforge.core.context import ScanContext
from reconforge.core.ratelimit import retry_call
from reconforge.core.registry import register_module
from reconforge.core.target import Target
from reconforge.integrations import shodan_api, virustotal

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "cpanel", "whm",
    "autodiscover", "autoconfig", "m", "imap", "test", "blog", "pop3", "dev", "www2",
    "admin", "forum", "news", "vpn", "mail2", "mysql", "old", "lists", "support",
    "mobile", "mx", "static", "docs", "beta", "shop", "sql", "secure", "demo", "cp",
    "calendar", "wiki", "web", "media", "email", "images", "img", "www1", "intranet",
    "portal", "video", "sip", "dns2", "api", "cdn", "stats", "dns1", "search",
    "staging", "server", "mx1", "chat", "wap", "my", "svn", "mail1", "sites",
    "proxy", "ads", "host", "ns", "ns3", "ns4", "git", "grafana", "jenkins", "jira",
    "status", "monitor", "backend", "db", "redis", "elastic", "kibana", "sso", "auth",
]

INTERESTING_EXTS = (
    ".sql", ".bak", ".old", ".zip", ".tar", ".gz", ".config", ".env", ".git",
    ".svn", ".db", ".dump", ".csv", ".key", ".pem",
)


@register_module(
    id="domain.whois",
    target_kinds=["domain"],
    profile="passive",
    description="WHOIS registration data (registrar, dates, contacts)",
)
def whois_lookup(target: Target, ctx: ScanContext):
    import whois

    def query():
        return whois.whois(target.value)

    data = retry_call(query, attempts=2, exceptions=(Exception,))
    creation = data.creation_date
    if isinstance(creation, list):
        creation = creation[0] if creation else None
    expiry = data.expiration_date
    if isinstance(expiry, list):
        expiry = expiry[0] if expiry else None
    emails = data.emails if isinstance(data.emails, list) else (
        [data.emails] if data.emails else []
    )
    result = {
        "registrar": data.registrar,
        "creation_date": str(creation) if creation else None,
        "expiration_date": str(expiry) if expiry else None,
        "name_servers": sorted({ns.lower() for ns in (data.name_servers or [])}),
        "emails": sorted({e.lower() for e in emails if isinstance(e, str)}),
        "org": data.org,
        "country": data.country,
        "status": data.status if isinstance(data.status, list) else [data.status],
    }
    findings = []
    if result["emails"]:
        findings.append(f"WHOIS exposes contact emails: {', '.join(result['emails'][:3])}")
    if creation:
        findings.append(f"Domain registered {str(creation)[:10]}")
    return result, findings


@register_module(
    id="domain.dns",
    target_kinds=["domain"],
    profile="passive",
    description="DNS record enumeration (A/AAAA/MX/NS/TXT/SOA/CNAME)",
)
def dns_enumeration(target: Target, ctx: ScanContext):
    records: dict[str, list[str]] = {}
    findings: list[str] = []
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"):
        try:
            answers = dns.resolver.resolve(target.value, rtype)
            records[rtype] = sorted(str(r) for r in answers)
        except Exception:
            records[rtype] = []
    txt_blob = " ".join(records.get("TXT", [])).lower()
    if "v=spf1" not in txt_blob:
        findings.append("No SPF record found - spoofing risk")
    try:
        dns.resolver.resolve(f"_dmarc.{target.value}", "TXT")
    except Exception:
        findings.append("No DMARC record found")
    return records, findings


@register_module(
    id="domain.subdomains",
    target_kinds=["domain"],
    profile="passive",
    description="Subdomain enumeration via crt.sh certificate transparency + DNS wordlist",
)
def subdomain_enumeration(target: Target, ctx: ScanContext):
    found: set[str] = set()

    resp = ctx.http(
        "GET", "https://crt.sh/",
        params={"q": f"%.{target.value}", "output": "json"},
    )
    if resp.status_code == 200:
        try:
            for entry in resp.json():
                for name in str(entry.get("name_value", "")).split("\n"):
                    name = name.strip().lower().replace("*.", "")
                    if name.endswith(target.value) and name != target.value:
                        found.add(name)
        except (ValueError, AttributeError):
            pass

    def probe(sub: str) -> str | None:
        fqdn = f"{sub}.{target.value}"
        try:
            socket.gethostbyname(fqdn)
            return fqdn
        except OSError:
            return None

    from reconforge.modules.common import chunked_map

    for result in chunked_map(probe, COMMON_SUBDOMAINS, max_workers=30):
        if result:
            found.add(result)

    subdomains = sorted(found)
    findings = []
    if len(subdomains) >= 10:
        findings.append(f"{len(subdomains)} subdomains - large attack surface")
    return {"count": len(subdomains), "subdomains": subdomains}, findings


@register_module(
    id="domain.ssl",
    target_kinds=["domain"],
    profile="passive",
    description="TLS certificate details (issuer, validity, SANs)",
)
def ssl_certificate(target: Target, ctx: ScanContext):
    context = ssl.create_default_context()
    with socket.create_connection((target.value, 443), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=target.value) as ssock:
            cert = ssock.getpeercert()
    sans = [v for kind, v in cert.get("subjectAltName", ()) if kind == "DNS"]
    issuer = dict(x for x in cert.get("issuer", ()))
    not_after = cert.get("notAfter")
    findings = []
    expired = False
    if not_after:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        expired = expiry < datetime.now(timezone.utc)
        if expired:
            findings.append(f"TLS certificate expired on {not_after}")
    if len(sans) > 5:
        findings.append(f"Certificate covers {len(sans)} SANs (hint at more subdomains)")
    return {
        "subject": dict(x for x in cert.get("subject", ())),
        "issuer": issuer,
        "not_before": cert.get("notBefore"),
        "not_after": not_after,
        "expired": expired,
        "subject_alt_names": sans,
    }, findings


@register_module(
    id="domain.technologies",
    target_kinds=["domain"],
    profile="passive",
    description="Web technology fingerprinting (server, CMS, analytics)",
)
def technology_detection(target: Target, ctx: ScanContext):
    resp = ctx.http("GET", f"https://{target.value}", timeout=15)
    body = resp.text.lower()
    tech = {
        "server": resp.headers.get("Server"),
        "powered_by": resp.headers.get("X-Powered-By"),
        "cms": None,
        "analytics": [],
        "status_code": resp.status_code,
    }
    findings = []
    if "wp-content" in body:
        tech["cms"] = "WordPress"
    elif "joomla" in body:
        tech["cms"] = "Joomla"
    elif "drupal" in body:
        tech["cms"] = "Drupal"
    if tech["cms"]:
        findings.append(f"CMS detected: {tech['cms']} - check for known CVEs")
    if "google-analytics" in body or "gtag" in body:
        tech["analytics"].append("Google Analytics")
    if "facebook.com/tr" in body:
        tech["analytics"].append("Facebook Pixel")
    return tech, findings


@register_module(
    id="domain.security_headers",
    target_kinds=["domain"],
    profile="passive",
    description="HTTP security header audit (HSTS, CSP, XFO, ...)",
)
def security_headers(target: Target, ctx: ScanContext):
    resp = ctx.http("GET", f"https://{target.value}", timeout=15)
    watched = [
        "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
        "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
        "X-XSS-Protection",
    ]
    present = {k: resp.headers.get(k) for k in watched if resp.headers.get(k)}
    missing = [k for k in watched if k not in present]
    findings = []
    if len(missing) >= 3:
        findings.append(f"{len(missing)} security headers missing: {', '.join(missing)}")
    if "Content-Security-Policy" in missing:
        findings.append("No Content-Security-Policy header (XSS mitigation absent)")
    return {"present": present, "missing": missing}, findings


@register_module(
    id="domain.robots",
    target_kinds=["domain"],
    profile="passive",
    description="robots.txt / sitemap analysis for hidden paths",
)
def robots_txt(target: Target, ctx: ScanContext):
    resp = ctx.http("GET", f"https://{target.value}/robots.txt", timeout=10)
    if resp.status_code != 200:
        return {"present": False}, []
    lines = resp.text.splitlines()
    disallowed = [
        line.split(":", 1)[1].strip()
        for line in lines
        if line.lower().startswith("disallow:") and ":" in line
    ]
    interesting = [
        p for p in disallowed
        if any(x in p.lower() for x in ("admin", "config", "backup", "private", "secret"))
    ]
    findings = []
    if interesting:
        findings.append(f"robots.txt hints at sensitive paths: {', '.join(interesting[:5])}")
    return {"present": True, "disallowed": disallowed, "interesting": interesting}, findings


@register_module(
    id="domain.wayback",
    target_kinds=["domain"],
    profile="passive",
    description="Wayback Machine history: old URLs and leaked file types",
)
def wayback_machine(target: Target, ctx: ScanContext):
    resp = ctx.http(
        "GET", "https://web.archive.org/cdx/search/cdx",
        params={
            "url": f"{target.value}/*", "output": "json",
            "collapse": "urlkey", "limit": 5000, "fl": "original",
        },
        timeout=45,
    )
    if resp.status_code != 200:
        return {"total_urls": 0, "interesting_urls": []}, []
    try:
        rows = resp.json()
    except ValueError:
        return {"total_urls": 0, "interesting_urls": []}, []
    urls = [row[0] for row in rows[1:] if isinstance(row, list) and row]
    interesting = [u for u in urls if any(ext in u.lower() for ext in INTERESTING_EXTS)]
    findings = []
    if interesting:
        findings.append(
            f"{len(interesting)} archived URLs look like leaked/config files"
        )
    return {
        "total_urls": len(urls),
        "interesting_urls": interesting[:100],
    }, findings


@register_module(
    id="domain.dorks",
    target_kinds=["domain"],
    profile="passive",
    description="Google dork pack for manual follow-up",
)
def google_dorks(target: Target, ctx: ScanContext):
    site = target.value
    dorks = [
        f"site:{site}",
        f"site:{site} filetype:pdf",
        f"site:{site} filetype:sql OR filetype:db",
        f"site:{site} filetype:bak OR filetype:old OR filetype:backup",
        f"site:{site} inurl:admin OR inurl:login OR inurl:dashboard",
        f"site:{site} intitle:\"index of\"",
        f"site:{site} inurl:wp-content",
        f"site:{site} intext:password OR intext:passwd",
        f"site:{site} inurl:config",
        f"site:{site} error | warning",
        f"site:{site} inurl:api OR inurl:graphql",
        f"site:{site} ext:env OR ext:ini OR ext:yml",
    ]
    return {"dorks": dorks}, []


@register_module(
    id="domain.shodan",
    target_kinds=["domain"],
    profile="passive",
    requires_keys=["SHODAN_API_KEY"],
    description="Shodan exposed-services lookup for resolved host",
)
def shodan_lookup(target: Target, ctx: ScanContext):
    ip = socket.gethostbyname(target.value)
    data = shodan_api.host_info(ip, ctx.keys["SHODAN_API_KEY"], ctx.session)
    findings = []
    if data.get("vulns"):
        findings.append(
            f"Shodan reports vulns: {', '.join(data['vulns'][:3])}"
        )
    if len(data.get("ports", [])) > 10:
        findings.append(f"{len(data['ports'])} exposed ports on {ip}")
    return data, findings


@register_module(
    id="domain.virustotal",
    target_kinds=["domain"],
    profile="passive",
    requires_keys=["VIRUSTOTAL_API_KEY"],
    description="VirusTotal domain reputation and community votes",
)
def virustotal_domain(target: Target, ctx: ScanContext):
    data = virustotal.domain_reputation(
        target.value, ctx.keys["VIRUSTOTAL_API_KEY"], ctx.session
    )
    findings = []
    stats = data.get("last_analysis_stats") or {}
    if stats.get("malicious", 0) > 0:
        findings.append(
            f"Domain flagged malicious by {stats['malicious']} AV vendors"
        )
    return data, findings


@register_module(
    id="domain.emails",
    target_kinds=["domain"],
    profile="passive",
    requires_keys=["HUNTER_API_KEY"],
    description="Email addresses associated with the domain via Hunter.io",
)
def email_harvest(target: Target, ctx: ScanContext):
    from reconforge.integrations import hunter

    data = hunter.domain_search(target.value, ctx.keys["HUNTER_API_KEY"], ctx.session)
    emails = [e["value"] for e in data.get("emails", []) if e.get("value")]
    findings = []
    if emails:
        findings.append(f"{len(emails)} email addresses found for the domain")
    data["emails_found"] = emails
    return data, findings


@register_module(
    id="domain.osint_links",
    target_kinds=["domain"],
    profile="passive",
    description="Curated OSINT lookup URLs for the domain (manual follow-up)",
)
def osint_links(target: Target, ctx: ScanContext):
    site = target.value
    links = {
        "SecurityTrails": f"https://securitytrails.com/domain/{site}/dns",
        "VirusTotal": f"https://www.virustotal.com/gui/domain/{site}",
        "Shodan": f"https://www.shodan.io/domain/{site}",
        "urlscan.io": f"https://urlscan.io/search/#domain:{site}",
        "Censys": f"https://search.censys.io/search?resource=domains&q={site}",
        "BuiltWith": f"https://builtwith.com/{site}",
        "Wayback": f"https://web.archive.org/web/*/{site}",
        "crt.sh": f"https://crt.sh/?q=%.{site}",
        "DNSdumpster": "https://dnsdumpster.com/",
        "Wappalyzer": f"https://www.wappalyzer.com/lookup/{site}",
        "BGPView": f"https://bgpview.io/search?q={site}",
        "HuntIntel": "https://intelligencehunter.com/",
    }
    return {"links": links}, []
