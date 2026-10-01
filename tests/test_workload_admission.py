"""Workload TLS admission must not require endpoint-specific certificate claims."""

import hashlib
from uuid import UUID

import pytest

from northgate_rmm.errors import ValidationError
from northgate_rmm.workload_service import workload_peer_identity


class WorkloadPeer:
    def __init__(self, certificate: bytes, version: str = "TLSv1.3") -> None:
        self.certificate = certificate
        self.tls_version = version

    def version(self) -> str:
        return self.tls_version

    def getpeercert(self, binary_form: bool = False) -> bytes | dict[str, object]:
        return self.certificate if binary_form else {}


def test_pinned_workload_uses_certificate_quota_without_endpoint_claims() -> None:
    # TLS verifies the chain before the admission callback receives the peer.
    certificate = b"tls-verified-workload-certificate-without-endpoint-uri"
    fingerprint = hashlib.sha256(certificate).hexdigest()
    assert workload_peer_identity(
        WorkloadPeer(certificate), frozenset({fingerprint})
    ) == (UUID(int=0), fingerprint)


@pytest.mark.parametrize(
    "peer",
    [
        None,
        WorkloadPeer(b""),
        WorkloadPeer(b"unknown"),
        WorkloadPeer(b"known", "TLSv1.2"),
    ],
)
def test_unverified_or_unpinned_workload_is_rejected(peer: WorkloadPeer | None) -> None:
    allowed = frozenset({hashlib.sha256(b"known").hexdigest()})
    with pytest.raises(ValidationError):
        workload_peer_identity(peer, allowed)
