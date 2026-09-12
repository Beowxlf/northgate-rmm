from __future__ import annotations

import io
import json
import ssl
import urllib.error
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from northgate_rmm.secrets_vault import NoRedirect, OpenBaoKV, VaultError


def client(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic provider CA")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    ca = tmp_path / "ca.pem"
    ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    token = tmp_path / "token"
    token.write_text("synthetic-token")
    token.chmod(0o600)
    return OpenBaoKV(
        {
            "origin": "https://vault.test:8200",
            "mount": "rmm",
            "ca_file": str(ca),
            "token_file": str(token),
        }
    )


def test_provider_pins_ca_sends_token_only_to_exact_origin_and_disallows_redirect(
    tmp_path,
):
    provider = client(tmp_path)
    assert provider.context.verify_mode == ssl.CERT_REQUIRED
    assert provider.context.check_hostname
    assert provider.context.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert len(provider.context.get_ca_certs()) == 1
    requests = []

    class Opener:
        def open(self, request, timeout):
            requests.append(request)
            assert timeout == 15
            return io.BytesIO(json.dumps({"data": {"version": 1}}).encode())

    provider.opener = Opener()
    assert provider.write("northgate-rmm/one", {"token": "synthetic"}, cas=0) == 1
    request = requests[0]
    assert request.full_url == "https://vault.test:8200/v1/rmm/data/northgate-rmm/one"
    assert request.get_header("X-vault-token") == "synthetic-token"
    assert json.loads(request.data)["options"]["cas"] == 0
    with pytest.raises(VaultError):
        NoRedirect().redirect_request(
            request, None, 302, "Found", {}, "https://other.test/"
        )
    provider.token_file.write_text("next-synthetic-token")
    provider.write("northgate-rmm/one", {"token": "synthetic"}, cas=1)
    assert requests[-1].get_header("X-vault-token") == "next-synthetic-token"
    provider.token_file.unlink()
    with pytest.raises(VaultError):
        provider.read("northgate-rmm/one")
    assert len(requests) == 2


def test_health_does_not_send_auth_and_sealed_provider_remains_readable(tmp_path):
    provider = client(tmp_path)
    provider.token_file.unlink()

    class Opener:
        def open(self, request, timeout):
            assert not request.get_header("X-vault-token")
            raise urllib.error.HTTPError(
                request.full_url,
                503,
                "Sealed",
                {},
                io.BytesIO(b'{"initialized":true,"sealed":true}'),
            )

    provider.opener = Opener()
    assert provider.health() == {"initialized": True, "sealed": True, "standby": False}


@pytest.mark.parametrize(
    "body", [b"[]", b'{"data":null}', b'{"data":{"version":"bad"}}']
)
def test_invalid_provider_response_is_sanitized(tmp_path, body):
    provider = client(tmp_path)

    class Opener:
        def open(self, request, timeout):
            return io.BytesIO(body)

    provider.opener = Opener()
    with pytest.raises(VaultError, match="Secret provider request failed"):
        provider.write("northgate-rmm/one", {"token": "synthetic"}, cas=0)


def test_missing_ca_is_sanitized(tmp_path):
    with pytest.raises(VaultError, match="Secret provider request failed"):
        OpenBaoKV(
            {
                "origin": "https://vault.test",
                "mount": "rmm",
                "ca_file": str(tmp_path / "missing"),
                "token_file": "unused",
            }
        )
