import pytest

from subwatch.scanner import extract_title, normalize_domain, parse_crt_response, parse_domains
from subwatch.app import Subwatch


def test_response_is_cleaned_deduplicated_and_scoped():
    text = "WWW.Example.com\n*.api.example.com\nevil-example.com\nexample.com.\ninvalid host\n"
    assert parse_crt_response(text, "example.com") == ["example.com", "api.example.com", "www.example.com"]


def test_domain_inputs_accept_urls_commas_and_idn():
    assert parse_domains(["https://Example.COM/path, café.example"]) == ["example.com", "xn--caf-dma.example"]


@pytest.mark.parametrize("value", ["", "bad host", "-bad.example", "bad..example"])
def test_invalid_domains(value):
    with pytest.raises(ValueError):
        normalize_domain(value)


async def test_tui_mounts(tmp_path):
    app = Subwatch([], concurrency=2, timeout=1, output=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app.query_one("#domains")
        assert len(app.query_one("DataTable").columns) == 6


def test_title_extraction_is_bounded_and_whitespace_normalized():
    assert extract_title("<HTML><TITLE> Hello   world </TITLE></HTML>") == "Hello world"
