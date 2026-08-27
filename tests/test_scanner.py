import pytest

from subwatch.scanner import discover, extract_title, normalize_domain, parse_crt_response, parse_domains
from subwatch.app import result_line, write_reports
from subwatch.openct import NameRecord
from subwatch.scanner import ProbeResult


def test_response_is_cleaned_deduplicated_and_scoped():
    text = "WWW.Example.com\n*.api.example.com\nevil-example.com\nexample.com.\ninvalid host\n"
    assert parse_crt_response(text, "example.com") == ["example.com", "api.example.com", "www.example.com"]


def test_domain_inputs_accept_urls_commas_and_idn():
    assert parse_domains(["https://Example.COM/path, café.example"]) == ["example.com", "xn--caf-dma.example"]


@pytest.mark.parametrize("value", ["", "bad host", "-bad.example", "bad..example"])
def test_invalid_domains(value):
    with pytest.raises(ValueError):
        normalize_domain(value)


def test_public_result_line_contains_useful_fields():
    item = ProbeResult("example.com", "www.example.com", "public", "https://www.example.com", 200, elapsed_ms=42)
    assert "[+] www.example.com  200  https://www.example.com  (42 ms)" in result_line(item).plain


def test_json_report_is_opt_in(tmp_path):
    item = ProbeResult("example.com", "www.example.com", "public", status=200)
    assert write_reports([item], tmp_path, False, False) == []
    written = write_reports([item], tmp_path, True, False)
    assert written == [tmp_path / "subwatch-results.json"]
    assert '\"host\": \"www.example.com\"' in written[0].read_text()


def test_title_extraction_is_bounded_and_whitespace_normalized():
    assert extract_title("<HTML><TITLE> Hello   world </TITLE></HTML>") == "Hello world"


async def test_openct_discovery_is_on_demand(monkeypatch):
    async def fake_fetch(apex, max_pages, timeout):
        assert (apex, max_pages) == ("example.com", 3)
        return [NameRecord("example.com", "www.example.com", "")]

    monkeypatch.setattr("subwatch.openct.fetch_certspotter", fake_fetch)
    class Client:
        class Timeout:
            read = 4.0
        timeout = Timeout()
    assert await discover(Client(), "example.com", source="openct", max_pages=3) == ["www.example.com"]
