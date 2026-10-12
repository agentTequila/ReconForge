"""platforms.json integrity tests (community data must stay valid)."""

from reconforge.modules.username import load_platforms


def test_platform_count():
    platforms = load_platforms()
    assert len(platforms) >= 60, "keep the 60+ platform promise"


def test_urls_contain_placeholder():
    for p in load_platforms():
        assert "{username}" in p["url"], p["name"] + " missing {username} placeholder"
        assert p["url"].startswith("https://"), f"{p['name']} must use https"


def test_names_unique_and_fields_present():
    names = [p["name"] for p in load_platforms()]
    assert len(names) == len(set(names))
    for p in load_platforms():
        assert p.get("category")
        assert "not_found_codes" in p or "not_found_marker" in p or "body_marker" in p


def test_categories_cover_popular_areas():
    cats = {p["category"] for p in load_platforms()}
    assert {"dev", "social", "gaming", "media"} <= cats
