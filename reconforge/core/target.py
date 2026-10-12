"""Target parsing, validation and kind auto-detection."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

TARGET_KINDS = ("domain", "email", "phone", "person", "username", "ip")

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_PHONE_RE = re.compile(r"^\+?[0-9]{7,15}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)


class TargetError(ValueError):
    """Raised when a target value cannot be parsed or validated."""


@dataclass
class Target:
    kind: str
    value: str
    meta: dict = field(default_factory=dict)

    def __str__(self) -> str:
        return f"{self.kind}:{self.value}"


def clean_domain(raw: str) -> str:
    domain = raw.strip().lower()
    if "://" in domain:
        parsed = urlparse(domain)
        domain = parsed.netloc
    domain = domain.split("/")[0].split("?")[0]
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def detect_kind(value: str) -> str | None:
    value = value.strip()
    if not value:
        return None
    if _EMAIL_RE.match(value):
        return "email"
    try:
        ipaddress.ip_address(value.strip("[]"))
        return "ip"
    except ValueError:
        pass
    if re.fullmatch(r"[\d\s()+\-.]{7,}", value) and len(re.sub(r"\D", "", value)) >= 7:
        return "phone"
    if " " in value:
        return "person"
    candidate = clean_domain(value)
    if _DOMAIN_RE.match(candidate):
        return "domain"
    if _USERNAME_RE.match(value.lstrip("@")):
        return "username"
    return None


def parse_target(value: str, kind: str | None = None) -> Target:
    value = value.strip()
    if not value:
        raise TargetError("empty target")
    if kind is None:
        kind = detect_kind(value)
        if kind is None:
            raise TargetError(
                f"cannot auto-detect target type for {value!r}; use --type "
                f"({'|'.join(TARGET_KINDS)})"
            )
    if kind not in TARGET_KINDS:
        raise TargetError(f"unknown target type: {kind}")

    if kind == "domain":
        domain = clean_domain(value)
        if not _DOMAIN_RE.match(domain):
            raise TargetError(f"invalid domain: {value!r}")
        return Target("domain", domain)

    if kind == "email":
        email = value.lower()
        if not _EMAIL_RE.match(email):
            raise TargetError(f"invalid email: {value!r}")
        local, domain = email.split("@", 1)
        return Target("email", email, {"local": local, "domain": domain})

    if kind == "phone":
        digits = re.sub(r"[^\d+]", "", value)
        if not _PHONE_RE.match(digits):
            raise TargetError(f"invalid phone number: {value!r}")
        if not digits.startswith("+"):
            digits = "+" + digits
        return Target("phone", digits)

    if kind == "ip":
        try:
            ip = str(ipaddress.ip_address(value.strip("[]")))
        except ValueError as exc:
            raise TargetError(f"invalid IP address: {value!r}") from exc
        return Target("ip", ip)

    if kind == "username":
        username = value.lstrip("@")
        if not _USERNAME_RE.match(username):
            raise TargetError(f"invalid username: {value!r}")
        return Target("username", username)

    name = re.sub(r"\s+", " ", value)
    if len(name) < 2:
        raise TargetError("person name too short")
    return Target("person", name)
