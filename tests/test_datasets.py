from subwatch.datasets import records_from_text


def test_dataset_extraction_normalizes_and_deduplicates():
    records = records_from_text(
        "https://WWW.Example.com/a\n0.0.0.0 api.example.co.uk\n*.www.example.com\n",
        "commoncrawl", "2024-01-01T00:00:00Z",
    )
    assert {(record.apex, record.subdomain) for record in records} == {
        ("example.com", "www.example.com"),
        ("example.co.uk", "api.example.co.uk"),
    }
