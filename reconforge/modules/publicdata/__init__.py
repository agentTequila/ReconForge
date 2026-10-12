"""Public data / leak-index aggregator (URL generator modules)."""

from __future__ import annotations

from urllib.parse import quote

from reconforge.core.context import ScanContext
from reconforge.core.registry import register_module
from reconforge.core.target import Target

GENERAL = {
    "IntelligenceX": "https://intelx.io/?s={q}",
    "DeHashed": "https://www.dehashed.com/search?query={q}",
    "LeakCheck": "https://leakcheck.io/search?q={q}",
    "PublicRecords": "https://publicrecords.searchsystems.net/",
    "OpenCorporates": "https://opencorporates.com/companies?q={q}",
    "FamilySearch": "https://www.familysearch.org/search/record/results?q={q}",
    "Wikipedia": "https://en.wikipedia.org/w/index.php?search={q}",
    "Google News": "https://news.google.com/search?q={q}",
    "WHOIS History": "https://whoisrequest.com/",
    "Netcraft": "https://searchnetcraft.com/",
    "FBI Most Wanted": "https://www.fbi.gov/wanted",
    "SEC EDGAR": "https://www.sec.gov/edgar/searchedgar/companysearch.html",
}


@register_module(
    id="publicdata.searches",
    target_kinds=["person", "email", "username", "phone"],
    profile="passive",
    description="Aggregated public-record and leak-index search URLs",
)
def public_data_searches(target: Target, ctx: ScanContext):
    q = quote(target.value)
    links = {name: tpl.format(q=q) for name, tpl in GENERAL.items()}
    return {"query": target.value, "links": links,
            "note": "URL generators: open in a browser to complete the search"}, []
