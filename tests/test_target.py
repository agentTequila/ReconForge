"""Target parsing and auto-detection tests."""

import pytest

from reconforge.core.target import TargetError, detect_kind, parse_target


@pytest.mark.parametrize(
    "value,kind",
    [
        ("example.com", "domain"),
        ("https://www.example.com/path?q=1", "domain"),
        ("user@example.com", "email"),
        ("+441234567890", "phone"),
        ("0173829485", "phone"),
        ("John Q. Public", "person"),
        ("octocat", "username"),
        ("8.8.8.8", "ip"),
        ("2001:db8::1", "ip"),
    ],
)
def test_detect_kind(value, kind):
    assert detect_kind(value) == kind


def test_parse_domain_strips_scheme_and_www():
    target = parse_target("HTTPS://WWW.Example.COM/index.html")
    assert target.kind == "domain"
    assert target.value == "example.com"


def test_parse_email_meta():
    target = parse_target("Jane.Doe@Example.com")
    assert target.value == "jane.doe@example.com"
    assert target.meta == {"local": "jane.doe", "domain": "example.com"}


def test_parse_phone_normalizes_to_e164():
    target = parse_target("(017) 382-9485")
    assert target.value.startswith("+")
    assert target.value == "+0173829485"


def test_parse_username_strips_at():
    assert parse_target("@octocat").value == "octocat"


def test_invalid_email_raises():
    with pytest.raises(TargetError):
        parse_target("not-an-email", "email")


def test_invalid_domain_raises():
    with pytest.raises(TargetError):
        parse_target("not a domain!!", "domain")


def test_unknown_kind_raises():
    with pytest.raises(TargetError):
        parse_target("whatever", "spaceship")


def test_empty_target_raises():
    with pytest.raises(TargetError):
        parse_target("   ")
