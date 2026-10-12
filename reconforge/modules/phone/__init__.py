"""Phone number reconnaissance modules."""

from __future__ import annotations

from urllib.parse import quote

from reconforge.core.context import ScanContext
from reconforge.core.registry import register_module
from reconforge.core.target import Target
from reconforge.integrations import numverify

LINKS = {
    "Truecaller": "https://www.truecaller.com/search/{num}",
    "WhitePages": "https://www.whitepages.com/phone/{num}",
    "Sync.me": "https://sync.me/search/?number={num}",
    "NumLookup": "https://www.numlookup.com/?number={num}",
    "CalledNumber": "https://callednumber.com/",
    "Whocalledus": "https://whocalledus.com/",
    "Google": "https://www.google.com/search?q={q}",
    "Facebook": "https://www.facebook.com/search/top?q={q}",
    "Telegram": "https://t.me/{num}",
}


@register_module(
    id="phone.details",
    target_kinds=["phone"],
    profile="passive",
    description="Number parsing: region, carrier, line type (phonenumbers lib)",
)
def phone_details(target: Target, ctx: ScanContext):
    try:
        import phonenumbers
    except ImportError:
        return {"note": "install 'phonenumbers' for deep number analysis"}, []

    parsed = phonenumbers.parse(target.value, None)
    region = phonenumbers.region_number_for_number(parsed)
    carrier_name = phonenumbers.carrier_name_for_number(parsed, "en")
    tz = phonenumbers.time_zones_for_number(parsed)
    valid = phonenumbers.is_valid_number(parsed)
    possible = phonenumbers.is_possible_number(parsed)
    number_type = phonenumbers.number_type(parsed)
    type_names = {
        0: "FIXED_LINE", 1: "MOBILE", 2: "FIXED_LINE_OR_MOBILE", 3: "TOLL_FREE",
        4: "PREMIUM_RATE", 5: "SHARED_COST", 6: "VOIP", 7: "PERSONAL_NUMBER",
        8: "PAGER", 9: "UAN", 10: "VOICEMAIL", -1: "UNKNOWN",
    }
    findings = []
    if not valid:
        findings.append("Number is not a valid E.164 number")
    if number_type in (3, 4):
        findings.append(f"Premium/toll-free number type: {type_names.get(number_type)}")
    return {
        "valid": valid,
        "possible": possible,
        "region": region,
        "carrier": carrier_name or None,
        "line_type": type_names.get(number_type, "UNKNOWN"),
        "timezones": list(tz),
        "national_format": phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.NATIONAL
        ),
        "international_format": phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
        ),
    }, findings


@register_module(
    id="phone.carrier",
    target_kinds=["phone"],
    profile="passive",
    requires_keys=["NUMVERIFY_API_KEY"],
    description="Carrier/location lookup via NumVerify",
)
def carrier_lookup(target: Target, ctx: ScanContext):
    data = numverify.validate(target.value, ctx.keys["NUMVERIFY_API_KEY"], ctx.session)
    findings = []
    if data.get("valid"):
        findings.append(
            f"Number registered in {data.get('country_name')} "
            f"({data.get('carrier') or 'carrier unknown'})"
        )
    return data, findings


@register_module(
    id="phone.osint_links",
    target_kinds=["phone"],
    profile="passive",
    description="Caller-lookup and social search URLs for the number",
)
def phone_links(target: Target, ctx: ScanContext):
    num, q = target.value.lstrip("+"), quote(target.value)
    links = {name: tpl.format(num=num, q=q) for name, tpl in LINKS.items()}
    return {"links": links}, []
