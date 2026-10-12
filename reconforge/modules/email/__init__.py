"""Email reconnaissance modules."""

from __future__ import annotations

import hashlib
import smtplib
from urllib.parse import quote

import dns.resolver

from reconforge.core.context import ScanContext
from reconforge.core.registry import register_module
from reconforge.core.target import Target
from reconforge.integrations import emailrep, hibp

SOCIAL_TEMPLATES = {
    "Google": "https://www.google.com/search?q={q}",
    "GitHub": "https://github.com/search?q={q}&type=users",
    "LinkedIn": "https://www.google.com/search?q=site%3Alinkedin.com+{q}",
    "X / Twitter": "https://x.com/search?q={q}",
    "Facebook": "https://www.facebook.com/search/top?q={q}",
    "Reddit": "https://www.reddit.com/search/?q={q}",
    "Medium": "https://medium.com/search?q={q}",
}

BREACH_TOOLS = {
    "HaveIBeenPwned": "https://haveibeenpwned.com/account/{email}",
    "DeHashed": "https://www.dehashed.com/search?query={email}",
    "IntelligenceX": "https://intelx.io/?s={email}",
    "LeakCheck": "https://leakcheck.io/search?q={email}",
    "Mozilla Monitor": "https://monitor.mozilla.org/",
}


@register_module(
    id="email.breach",
    target_kinds=["email"],
    profile="passive",
    requires_keys=["HIBP_API_KEY"],
    description="Data breach history via Have I Been Pwned",
)
def breach_check(target: Target, ctx: ScanContext):
    data = hibp.breached_account(target.value, ctx.keys["HIBP_API_KEY"], ctx.session)
    findings = []
    if data.get("breach_count", 0):
        names = [b["name"] for b in data.get("breaches", [])[:5]]
        findings.append(
            f"Email appears in {data['breach_count']} breaches: {', '.join(names)}"
        )
        all_classes = {
            c for b in data.get("breaches", []) for c in b.get("data_classes", [])
        }
        if "Passwords" in all_classes:
            findings.append("Plaintext/hashed passwords exposed in a breach - "
                            "treat as compromised")
    return data, findings


@register_module(
    id="email.reputation",
    target_kinds=["email"],
    profile="passive",
    requires_keys=["EMAILREP_API_KEY"],
    description="Email reputation and deliverability signals via EmailRep",
)
def reputation_check(target: Target, ctx: ScanContext):
    data = emailrep.reputation(target.value, ctx.keys["EMAILREP_API_KEY"], ctx.session)
    findings = []
    if data.get("suspicious"):
        findings.append("Email flagged as suspicious by EmailRep")
    details = data.get("details") or {}
    if details.get("spam"):
        findings.append("Email associated with spam activity")
    if details.get("credential_leaked"):
        findings.append("Credentials for this email leaked previously")
    return data, findings


@register_module(
    id="email.mx",
    target_kinds=["email"],
    profile="passive",
    description="MX record validation for the email domain",
)
def mx_check(target: Target, ctx: ScanContext):
    domain = target.meta["domain"]
    answers = dns.resolver.resolve(domain, "MX")
    mx = sorted(
        (str(r.exchange).rstrip("."), r.preference) for r in answers
    )
    findings = []
    if not mx:
        findings.append("No MX records - mail domain misconfigured")
    return {"domain": domain, "mx_records": mx}, findings


@register_module(
    id="email.gravatar",
    target_kinds=["email"],
    profile="passive",
    description="Gravatar profile lookup (MD5 hash check)",
)
def gravatar_lookup(target: Target, ctx: ScanContext):
    digest = hashlib.md5(target.value.lower().encode("utf-8")).hexdigest()
    resp = ctx.http("GET", f"https://www.gravatar.com/{digest}.json", timeout=10)
    found = resp.status_code == 200
    profile = {}
    if found:
        try:
            entry = (resp.json().get("entry") or [{}])[0]
            profile = {
                "display_name": entry.get("displayName"),
                "location": entry.get("currentLocation"),
                "urls": [u.get("value") for u in entry.get("urls", [])],
                "photos": [p.get("value") for p in entry.get("photos", [])],
            }
        except ValueError:
            found = False
    findings = []
    if found and (profile.get("photos") or profile.get("location")):
        findings.append("Gravatar profile reveals photo/location - possible identity link")
    return {"found": found, "hash": digest, "profile": profile}, findings


@register_module(
    id="email.patterns",
    target_kinds=["email"],
    profile="passive",
    description="Analyze local-part naming pattern (first.last, flast, ...)",
)
def pattern_analysis(target: Target, ctx: ScanContext):
    local, domain = target.meta["local"], target.meta["domain"]
    guesses = {
        "first.last": f"firstname.lastname@{domain}",
        "firstlast": f"firstlast@{domain}",
        "f.last": f"f.lastname@{domain}",
        "first_l": f"first_l@{domain}",
        "last": f"lastname@{domain}",
    }
    if "." in local:
        parts = local.split(".")
        guesses["detected"] = f"dot-separated ({len(parts)} parts)"
    elif "_" in local:
        guesses["detected"] = "underscore-separated"
    else:
        guesses["detected"] = "single token / nickname"
    return {"local_part": local, "convention": guesses}, []


@register_module(
    id="email.osint_links",
    target_kinds=["email"],
    profile="passive",
    description="Search + breach-check URLs for the email address",
)
def email_links(target: Target, ctx: ScanContext):
    q = quote(target.value)
    links = {
        **{name: tpl.format(q=q) for name, tpl in SOCIAL_TEMPLATES.items()},
        **{name: tpl.format(email=target.value) for name, tpl in BREACH_TOOLS.items()},
    }
    return {"links": links}, []


@register_module(
    id="email.smtp",
    target_kinds=["email"],
    profile="active",
    description="SMTP RCPT TO verification against the MX server",
)
def smtp_verify(target: Target, ctx: ScanContext):
    domain = target.meta["domain"]
    mx_host = str(dns.resolver.resolve(domain, "MX")[0].exchange).rstrip(".")
    with smtplib.SMTP(timeout=10) as server:
        server.connect(mx_host)
        server.helo("reconforge.local")
        server.mail("probe@reconforge.local")
        code, message = server.rcpt(target.value)
        server.quit()
    text = message.decode() if isinstance(message, bytes) else str(message)
    findings = []
    if code == 250:
        findings.append("Mailbox confirmed to exist (SMTP 250)")
    return {"mx_host": mx_host, "code": code, "response": text,
            "mailbox_exists": code == 250}, findings
