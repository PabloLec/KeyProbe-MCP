import base64
import datetime as dt
import ipaddress
import pytest
from fastmcp import Client

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def _make_selfsigned_cert_pem() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Test CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "KeyProbe Test"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        ]
    )
    now = dt.datetime.now(dt.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("example.com"), x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]
            ),
            critical=False,
        )
    )
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.mark.asyncio
async def test_file_metadata_includes_x509(tmp_path):
    pem = _make_selfsigned_cert_pem()
    p = tmp_path / "cert.pem"
    p.write_bytes(pem)

    from keyprobe.server import mcp
    async with Client(mcp) as client:
        res = await client.call_tool("file_metadata", {"path": str(p)})
        meta = res.data
        assert meta["format"] == "PEM"
        assert "x509" in meta
        x = meta["x509"]
        assert x["subject_cn"] == "Test CN"
        assert x["issuer_cn"] == "Test CN"
        # Dates au format ISO8601Z
        assert x["not_before"].endswith("Z") and x["not_after"].endswith("Z")
        # SAN contient DNS et IP (ordre non garanti)
        assert set(x["san"]) >= {"example.com", "127.0.0.1"}
        # public key info
        assert x["public_key"]["type"] in ("EC", "EllipticCurvePublicKey")
        assert x["signature_hash"] in ("sha256", "sha256WithRSAEncryption", "sha256_ecdsa", "sha256")  # tolérant


@pytest.mark.asyncio
async def test_file_metadata_from_b64_includes_x509():
    pem = _make_selfsigned_cert_pem()
    b64 = base64.b64encode(pem).decode("ascii")

    from keyprobe.server import mcp
    async with Client(mcp) as client:
        res = await client.call_tool(
            "file_metadata_from_b64", {"filename": "cert.pem", "content_b64": b64}
        )
        meta = res.data
        assert meta["format"] == "PEM"
        assert "x509" in meta
        assert meta["x509"]["subject_cn"] == "Test CN"
