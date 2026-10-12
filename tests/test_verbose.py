"""Flavor-text tests (reconforge.core.verbose)."""

import random

from reconforge.core.verbose import flavor_for


def test_known_modules_get_bank_lines():
    rng = random.Random(0)
    for mid in ("domain.crtsh", "domain.subdomains", "domain.wayback",
                "domain.shodan", "ip.nmap", "domain.urlscan", "ip.bgp"):
        line = flavor_for(mid, rng=rng)
        assert isinstance(line, str) and line


def test_unknown_module_falls_back_to_generic():
    rng = random.Random(0)
    line = flavor_for("weird.module", rng=rng)
    assert isinstance(line, str) and line


def test_flavor_is_deterministic_with_seed():
    a = flavor_for("domain.crtsh", rng=random.Random(7))
    b = flavor_for("domain.crtsh", rng=random.Random(7))
    assert a == b
