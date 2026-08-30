from datetime import UTC, datetime
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.x509.oid import ExtendedKeyUsageOID

from tests.support.pki import issue_test_endpoint_credential

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)


def test_test_ca_issues_short_lived_endpoint_bound_client_certificate() -> None:
    endpoint_id = uuid4()
    credentials = issue_test_endpoint_credential(endpoint_id, now=NOW)

    root_constraints = credentials.root_certificate.extensions.get_extension_for_class(
        x509.BasicConstraints
    ).value
    endpoint_constraints = (
        credentials.endpoint_certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    )
    endpoint_usage = (
        credentials.endpoint_certificate.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
    )
    endpoint_names = (
        credentials.endpoint_certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    )

    assert root_constraints.ca is True
    assert endpoint_constraints.ca is False
    assert endpoint_usage == x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])
    assert endpoint_names.get_values_for_type(x509.UniformResourceIdentifier) == [
        f"urn:northgate-rmm:endpoint:{endpoint_id}"
    ]
    assert credentials.endpoint_certificate.not_valid_after_utc > NOW

    root_public_key = credentials.root_certificate.public_key()
    assert isinstance(root_public_key, Ed25519PublicKey)
    root_public_key.verify(
        credentials.endpoint_certificate.signature,
        credentials.endpoint_certificate.tbs_certificate_bytes,
    )
