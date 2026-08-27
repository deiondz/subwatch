import base64
import struct
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from subwatch.ctlog import certificate_from_entry, parse_log_list, records_from_entry


def make_certificate() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "www.example.com")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(1).not_valid_before(now).not_valid_after(now.replace(year=now.year + 1))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("www.example.com"), x509.DNSName("*.api.example.co.uk")
        ]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def leaf_entry(cert: bytes, timestamp_ms: int = 1_700_000_000_000) -> dict:
    leaf = b"\x00\x00" + struct.pack(">QH", timestamp_ms, 0) + len(cert).to_bytes(3, "big") + cert + b"\x00\x00"
    return {"leaf_input": base64.b64encode(leaf).decode(), "extra_data": ""}


def test_x509_leaf_and_san_parsing():
    cert = make_certificate()
    parsed, timestamp = certificate_from_entry(leaf_entry(cert))
    assert parsed == cert
    assert timestamp == 1_700_000_000_000
    records = records_from_entry(leaf_entry(cert))
    assert {(r.apex, r.subdomain) for r in records} == {
        ("example.com", "www.example.com"), ("example.co.uk", "api.example.co.uk")
    }


def test_log_list_parsing():
    payload = {"operators": [{"logs": [{
        "log_id": "abc", "description": "Test Log", "url": "https://ct.example/",
        "state": {"usable": {"timestamp": "2025-01-01T00:00:00Z"}},
    }]}]}
    log = parse_log_list(payload, "chrome")[0]
    assert (log.log_id, log.state, log.program) == ("abc", "usable", "chrome")
