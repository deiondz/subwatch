import json
from urllib.parse import urljoin

from subwatch.openct import Index, NameRecord, names_from_issuances, next_link, render


def test_issuance_names_are_normalized_deduplicated_and_scoped():
    payload = [
        {"not_before": "2024-02-01T00:00:00Z", "dns_names": ["*.API.Example.com", "other.net"]},
        {"not_before": "2024-01-01T00:00:00Z", "dns_names": ["api.example.com", "example.com"]},
    ]
    assert names_from_issuances(payload, "example.com") == [
        NameRecord("example.com", "example.com", "2024-01-01T00:00:00Z"),
        NameRecord("example.com", "api.example.com", "2024-01-01T00:00:00Z"),
    ]


def test_index_keeps_earliest_seen_date(tmp_path):
    index = Index(tmp_path / "openct.db")
    index.upsert([NameRecord("example.com", "www.example.com", "2024-02-01T00:00:00Z")])
    index.upsert([NameRecord("example.com", "www.example.com", "2024-01-01T00:00:00Z")])
    assert index.search("example.com")[0].first_seen == "2024-01-01T00:00:00Z"


def test_render_matches_newline_api_and_json_modes():
    records = [NameRecord("example.com", "www.example.com", "2024-01-01T00:00:00Z")]
    assert render(records, "text", False) == "www.example.com\n"
    assert render(records, "text", True) == "www.example.com\t2024-01-01T00:00:00Z\n"
    assert json.loads(render(records, "json", False)) == ["www.example.com"]


def test_link_header_pagination():
    value = '<https://api.example.test/page2>; rel="next", <https://api.example.test/page4>; rel="last"'
    assert next_link(value) == "https://api.example.test/page2"


def test_relative_pagination_link_is_resolved_against_response_url():
    value = '</v1/issuances?domain=example.com&after=123>; rel="next"'
    assert urljoin("https://api.certspotter.com/v1/issuances", next_link(value)) == (
        "https://api.certspotter.com/v1/issuances?domain=example.com&after=123"
    )
