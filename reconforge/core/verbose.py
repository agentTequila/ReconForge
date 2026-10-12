"""Fancy scan status lines - the OSINT flavor text shown while modules run.

``flavor_for("domain.crtsh")`` -> "sifting through certificate ashes"

Frontends show one line per module start so a scan feels like a story
instead of a silent wait.
"""

from __future__ import annotations

import random

_GENERIC = [
    "mapping the attack surface",
    "collecting evidence",
    "sweeping for footprints",
    "following the digital paper trail",
    "dusting for fingerprints",
    "triangulating the signal",
    "reading between the firewall lines",
    "counting doors in the dark",
    "patrolling the back alleys of the internet",
    "panning for gold in data streams",
    "piecing together the mosaic",
    "checking the internet's attic",
    "interrogating public records",
    "listening to the wiretaps (the legal kind)",
    "connecting the dots",
    "watching the watchers",
]

_BANKS: dict[str, list[str]] = {
    "crt": [
        "sifting through certificate ashes",
        "reading CT log diaries",
        "unsealing Certificate Transparency archives",
        "checking who signed what, and when",
    ],
    "dns": [
        "consulting the internet's phone book",
        "asking DNS servers to confess",
        "tracing names down to numbers",
    ],
    "whois": [
        "knocking on WHOIS doors",
        "reading the registration fine print",
    ],
    "subdomain": [
        "counting hidden rooms in the house",
        "expanding the map's edges",
        "knocking on subdomain doors",
    ],
    "wayback": [
        "rummaging through the internet's attic",
        "dusting off archived pages",
        "time-traveling through old snapshots",
    ],
    "shodan": [
        "waking Shodan's sleepless eyes",
        "checking what glows in the dark",
        "asking the search engine for exposed things",
    ],
    "threat": [
        "cross-referencing the wanted posters",
        "checking the threat-intel blotter",
        "patrolling with the usual suspects' files open",
    ],
    "breach": [
        "rifling through breach dust",
        "reading the gossip indexes",
        "checking if passwords had a bad day",
    ],
    "harvest": [
        "harvesting addresses from public records",
        "scraping the contact boards",
        "following @ handles like breadcrumbs",
    ],
    "social": [
        "knocking on64+ front doors",
        "checking the social registry",
        "sweeping the usual hangouts",
    ],
    "phone": [
        "tracing the caller's footprints",
        "checking the switchboard gossip",
        "listening for ring patterns",
    ],
    "person": [
        "dusting off the paper trail",
        "consulting the directories",
        "matching names to histories",
    ],
    "nmap": [
        "knocking on doors (politely, with nmap)",
        "counting open doors",
        "listening for services to introduce themselves",
    ],
    "port": [
        "counting open doors",
        "walking the hallways of ports",
    ],
    "url": [
        "peeking at the footprints visitors left behind",
        "reading the web's visitor log",
        "checking screenshots of the scene",
    ],
    "bgp": [
        "following the routing breadcrumbs",
        "tracing the mail through postal routes",
    ],
    "mail": [
        "interrogating the mail servers",
        "checking return addresses",
        "reading the postmarks",
    ],
    "header": [
        "checking the paint on the walls (headers)",
        "inspecting the furniture's fingerprints",
    ],
    "ai": [
        "letting the model connect the dots",
        "reading the tea leaves",
        "asking the oracle politely",
    ],
}

# (keyword, bank) - first match on the module id wins; order matters
_KEYWORDS = (
    ("crt", ("crtsh", "ct_log", "ssl", "cert")),
    ("dns", ("dns", "resolve", "rdap")),
    ("whois", ("whois",)),
    ("subdomain", ("subdomain", "hackertarget", "hostsearch")),
    ("wayback", ("wayback", "archive")),
    ("shodan", ("shodan",)),
    ("threat", ("virustotal", "abuse", "urlhaus", "greynoise", "threat")),
    ("breach", ("breach", "pwned", "hibp")),
    ("harvest", ("hunter", "email", "emails")),
    ("social", ("social", "username", "platform")),
    ("phone", ("phone", "numverify", "sms")),
    ("person", ("person", "name")),
    ("nmap", ("nmap",)),
    ("port", ("port", "service")),
    ("url", ("urlscan", "url", "robots", "dork", "directories")),
    ("bgp", ("bgp", "asn")),
    ("mail", ("mx", "spf", "dmarc")),
    ("header", ("header", "technolog", "fingerprint")),
    ("ai", ("ai", "analyze")),
)


def flavor_for(module_id: str, rng: random.Random | None = None) -> str:
    """Return a random flavor line matched to the module (or generic)."""
    pick = rng.choice if rng else random.choice
    lowered = module_id.lower()
    for bank_name, keywords in _KEYWORDS:
        if any(k in lowered for k in keywords):
            return pick(_BANKS[bank_name])
    return pick(_GENERIC)
