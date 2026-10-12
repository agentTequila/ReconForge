"""Person (name) reconnaissance modules."""

from __future__ import annotations

from urllib.parse import quote

from reconforge.core.context import ScanContext
from reconforge.core.registry import register_module
from reconforge.core.target import Target

SOCIAL = {
    "Google": "https://www.google.com/search?q={q}",
    "Google Images": "https://www.google.com/search?tbm=isch&q={q}",
    "LinkedIn": "https://www.linkedin.com/search/results/people/?keywords={q}",
    "Facebook": "https://www.facebook.com/search/people?q={q}",
    "X / Twitter": "https://x.com/search?q={q}&f=user",
    "Instagram": "https://www.instagram.com/explore/tags/{tag}/",
    "GitHub": "https://github.com/search?q={q}&type=users",
    "Reddit": "https://www.reddit.com/search/?q={q}",
    "Medium": "https://medium.com/search?q={q}",
    "YouTube": "https://www.youtube.com/results?search_query={q}",
    "TikTok": "https://www.tiktok.com/search?q={q}",
    "Twitch": "https://www.twitch.tv/search?term={q}",
    "Pinterest": "https://www.pinterest.com/search/pins/?q={q}",
    "Telegram": "https://t.me/s/{tag}",
    "Keybase": "https://keybase.io/_/search?q={q}",
}

PUBLIC_RECORDS = {
    "Pipl": "https://pipl.com/search/?q={q}",
    "Spokeo": "https://www.spokeo.com/search?q={q}",
    "WhitePages": "https://www.whitepages.com/name/{q}",
    "TruePeopleSearch": "https://www.truepeoplesearch.com/results?name={q}",
    "FastPeopleSearch": "https://www.fastpeoplesearch.com/name/{q}",
    "Radaris": "https://radaris.com/search?query={q}",
    "BeenVerified": "https://www.beenverified.com/",
    "ThatsThem": "https://thatsthem.com/search?query={q}",
}

PROFESSIONAL = {
    "LinkedIn": "https://www.linkedin.com/search/results/people/?keywords={q}",
    "Crunchbase": "https://www.crunchbase.com/discover/people?query={q}",
    "AngelList / Wellfound": "https://wellfound.com/search?query={q}",
    "Google Scholar": "https://scholar.google.com/scholar?q={q}",
    "ResearchGate": "https://www.researchgate.net/search/researcher?q={q}",
    "ORCID": "https://orcid.org/orcid-search/search?searchQuery={q}",
}

BREACH_TOOLS = {
    "IntelligenceX": "https://intelx.io/?s={q}",
    "DeHashed": "https://www.dehashed.com/search?query={q}",
    "LeakCheck": "https://leakcheck.io/search?q={q}",
    "Google Leaks": "https://www.google.com/search?q={q}+leak",
}


def _render(template: dict, query: str) -> dict:
    tag = query.replace(" ", "")
    return {name: tpl.format(q=query, quote=quote(query), tag=quote(tag))
            for name, tpl in template.items()}


@register_module(
    id="person.social",
    target_kinds=["person"],
    profile="passive",
    description="Social media profile search URLs (15 platforms)",
)
def social_search(target: Target, ctx: ScanContext):
    return {"links": _render(SOCIAL, target.value)}, []


@register_module(
    id="person.public_records",
    target_kinds=["person"],
    profile="passive",
    description="People-search / public records engine URLs",
)
def public_records(target: Target, ctx: ScanContext):
    return {"links": _render(PUBLIC_RECORDS, target.value)}, []


@register_module(
    id="person.professional",
    target_kinds=["person"],
    profile="passive",
    description="Professional and academic network URLs",
)
def professional(target: Target, ctx: ScanContext):
    return {"links": _render(PROFESSIONAL, target.value)}, []


@register_module(
    id="person.breach_links",
    target_kinds=["person"],
    profile="passive",
    description="Breach/leak search engine URLs",
)
def breach_links(target: Target, ctx: ScanContext):
    return {"links": _render(BREACH_TOOLS, target.value)}, []


@register_module(
    id="person.username_ideas",
    target_kinds=["person"],
    profile="passive",
    description="Generate likely username variants from a full name",
)
def username_ideas(target: Target, ctx: ScanContext):
    parts = target.value.lower().split()
    first, last = parts[0], parts[-1]
    f = first[0]
    candidates = {
        f"{first}{last}", f"{first}.{last}", f"{first}_{last}", f"{first}-{last}",
        f"{f}{last}", f"{f}.{last}", f"{f}_{last}", f"{last}{first}",
        f"{first}{last}1", f"{first}{last}{str(2026)[-2:]}",
        f"{f}{last}{f}", f"{first}{f}{last}", f"{last}.{first}",
        f"{first}{last}_", f"the{first}{last}", f"{first}official",
    }
    variants = sorted(candidates)
    return {"name": target.value, "variants": variants,
            "note": "Check variants against username.platforms via "
                    "`reconforge scan <variant> --type username`"}, []
