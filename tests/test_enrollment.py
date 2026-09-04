from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID
from psycopg import OperationalError

from northgate_rmm.domain import Endpoint, EndpointIdentity, EndpointLifecycle, Platform
from northgate_rmm.enrollment import (
    EndpointIssuanceRequest,
    EnrollmentApplication,
    EnrollmentRequest,
    EnrollmentResult,
    EnrollmentService,
    IssuedEndpointCredential,
)
from northgate_rmm.errors import (
    AuthorizationError,
    ServiceUnavailableError,
    ValidationError,
)
from northgate_rmm.listener import validate_endpoint_certificate

NOW = datetime(2026, 9, 3, 20, 0, tzinfo=UTC)


@dataclass
class RecordingEnrollmentStore:
    endpoint_id: UUID = field(default_factory=uuid4)
    identity_id: UUID = field(default_factory=uuid4)
    fingerprint: str | None = None
    activated: dict[str, object] | None = None

    def begin_endpoint_enrollment(
        self,
        *,
        token: str,
        public_key_fingerprint: str,
        now: datetime,
        actor_id: str = "enrollment-service",
    ) -> tuple[Endpoint, EndpointIdentity]:
        assert token == grant_value()
        assert actor_id == "enrollment-service"
        self.fingerprint = public_key_fingerprint
        identity = EndpointIdentity(
            identity_id=self.identity_id,
            endpoint_id=self.endpoint_id,
            public_key_fingerprint=public_key_fingerprint,
            created_at=now,
        )
        endpoint = Endpoint(
            endpoint_id=self.endpoint_id,
            display_name="debian-canary",
            platform=Platform.LINUX,
            architecture="amd64",
            identity_id=self.identity_id,
            enrolled_at=now,
        )
        return endpoint, identity

    def record_issued_endpoint_identity(
        self,
        identity_id: UUID,
        *,
        certificate_serial: str,
        certificate_issuer: str,
        certificate_not_before: datetime,
        certificate_not_after: datetime,
        now: datetime,
        actor_id: str = "enrollment-service",
    ) -> EndpointIdentity:
        assert identity_id == self.identity_id
        assert actor_id == "enrollment-service"
        assert self.fingerprint is not None
        self.activated = {
            "certificate_serial": certificate_serial,
            "certificate_issuer": certificate_issuer,
            "certificate_not_before": certificate_not_before,
            "certificate_not_after": certificate_not_after,
            "now": now,
        }
        return EndpointIdentity(
            identity_id=self.identity_id,
            endpoint_id=self.endpoint_id,
            public_key_fingerprint=self.fingerprint,
            created_at=now,
            status=EndpointLifecycle.ISSUED,
        )


class FailingBeginStore(RecordingEnrollmentStore):
    def begin_endpoint_enrollment(
        self,
        *,
        token: str,
        public_key_fingerprint: str,
        now: datetime,
        actor_id: str = "enrollment-service",
    ) -> tuple[Endpoint, EndpointIdentity]:
        del token, public_key_fingerprint, now, actor_id
        raise OperationalError("private database detail")


class FailingRecordStore(RecordingEnrollmentStore):
    def record_issued_endpoint_identity(
        self,
        identity_id: UUID,
        *,
        certificate_serial: str,
        certificate_issuer: str,
        certificate_not_before: datetime,
        certificate_not_after: datetime,
        now: datetime,
        actor_id: str = "enrollment-service",
    ) -> EndpointIdentity:
        del (
            identity_id,
            certificate_serial,
            certificate_issuer,
            certificate_not_before,
            certificate_not_after,
            now,
            actor_id,
        )
        raise OperationalError("private database detail")


class RejectingRecordStore(FailingRecordStore):
    def record_issued_endpoint_identity(
        self,
        identity_id: UUID,
        *,
        certificate_serial: str,
        certificate_issuer: str,
        certificate_not_before: datetime,
        certificate_not_after: datetime,
        now: datetime,
        actor_id: str = "enrollment-service",
    ) -> EndpointIdentity:
        del (
            identity_id,
            certificate_serial,
            certificate_issuer,
            certificate_not_before,
            certificate_not_after,
            now,
            actor_id,
        )
        raise ValidationError("issuer certificate lifetime is too long")


@dataclass
class FakeIssuer:
    root_certificate: x509.Certificate
    root_key: ec.EllipticCurvePrivateKey
    wrong_endpoint: bool = False
    requests: list[EndpointIssuanceRequest] = field(default_factory=list)
    issued_by_identity: dict[
        UUID, tuple[EndpointIssuanceRequest, IssuedEndpointCredential]
    ] = field(default_factory=dict)

    def issue_endpoint_certificate(
        self,
        request: EndpointIssuanceRequest,
        *,
        now: datetime,
    ) -> IssuedEndpointCredential:
        self.requests.append(request)
        prior = self.issued_by_identity.get(request.identity_id)
        if prior is not None:
            assert prior[0] == request
            return prior[1]
        csr = x509.load_der_x509_csr(request.csr_der)
        endpoint_id = uuid4() if self.wrong_endpoint else request.endpoint_id
        leaf = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [x509.NameAttribute(NameOID.COMMON_NAME, "NorthGate endpoint")]
                )
            )
            .issuer_name(self.root_certificate.subject)
            .public_key(csr.public_key())
            .serial_number(42)
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=12))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(endpoint_key_usage(), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.UniformResourceIdentifier(
                            f"urn:northgate-rmm:endpoint:{endpoint_id}"
                        )
                    ]
                ),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.root_key.public_key()
                ),
                critical=False,
            )
            .sign(self.root_key, algorithm=hashes.SHA256())
        )
        credential = IssuedEndpointCredential(
            leaf_certificate_der=leaf.public_bytes(serialization.Encoding.DER)
        )
        self.issued_by_identity[request.identity_id] = (request, credential)
        return credential


@dataclass
class StaticIssuer:
    credential: IssuedEndpointCredential

    def issue_endpoint_certificate(
        self,
        request: EndpointIssuanceRequest,
        *,
        now: datetime,
    ) -> IssuedEndpointCredential:
        del request, now
        return self.credential


@dataclass
class RecordingEnrollmentOperation:
    error: Exception | None = None
    calls: list[tuple[str, bytes, datetime]] = field(default_factory=list)

    def enroll(
        self,
        *,
        token: str,
        csr_der: bytes,
        now: datetime,
    ) -> EnrollmentResult:
        self.calls.append((token, csr_der, now))
        if self.error is not None:
            raise self.error
        return EnrollmentResult(
            endpoint_id=UUID("11111111-1111-4111-8111-111111111111"),
            identity_id=UUID("22222222-2222-4222-8222-222222222222"),
            leaf_certificate_der=b"leaf",
            intermediate_certificates_der=(b"intermediate",),
        )


def test_enrollment_proves_key_possession_and_activates_external_credential() -> None:
    root, root_key = issue_root()
    store = RecordingEnrollmentStore()
    issuer = FakeIssuer(root, root_key)
    service = EnrollmentService(store, issuer, issuer_trust_roots=(root,))
    key = ec.generate_private_key(ec.SECP256R1())

    result = service.enroll(token=grant_value(), csr_der=csr_for(key), now=NOW)

    assert result.endpoint_id == store.endpoint_id
    assert result.identity_id == store.identity_id
    assert len(issuer.requests) == 1
    assert issuer.requests[0].identity_id == store.identity_id
    assert issuer.requests[0].public_key_fingerprint == store.fingerprint
    assert store.activated is not None
    assert store.activated["certificate_serial"] == "2a"
    leaf = x509.load_der_x509_certificate(result.leaf_certificate_der)
    peer = validate_endpoint_certificate(leaf)
    assert peer.endpoint_id == store.endpoint_id
    assert peer.public_key_fingerprint == store.fingerprint


def test_enrollment_retry_recovers_the_same_issued_credential() -> None:
    root, root_key = issue_root()
    store = RecordingEnrollmentStore()
    issuer = FakeIssuer(root, root_key)
    service = EnrollmentService(store, issuer, issuer_trust_roots=(root,))
    csr_der = csr_for(ec.generate_private_key(ec.SECP256R1()))

    first = service.enroll(token=grant_value(), csr_der=csr_der, now=NOW)
    retry = service.enroll(
        token=grant_value(),
        csr_der=csr_der,
        now=NOW + timedelta(seconds=1),
    )

    assert retry == first
    assert len(issuer.requests) == 2
    assert issuer.requests[0] == issuer.requests[1]


def test_enrollment_rejects_csr_claims_before_consuming_a_grant() -> None:
    root, root_key = issue_root()
    store = RecordingEnrollmentStore()
    service = EnrollmentService(
        store,
        FakeIssuer(root, root_key),
        issuer_trust_roots=(root,),
    )
    key = ec.generate_private_key(ec.SECP256R1())
    claimed = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "claimed")]))
        .sign(key, algorithm=hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )

    with pytest.raises(ValidationError, match="unauthorized claims"):
        service.enroll(token=grant_value(), csr_der=claimed, now=NOW)
    assert store.fingerprint is None


def test_enrollment_leaves_pending_state_when_issuer_binding_is_wrong() -> None:
    root, root_key = issue_root()
    store = RecordingEnrollmentStore()
    service = EnrollmentService(
        store,
        FakeIssuer(root, root_key, wrong_endpoint=True),
        issuer_trust_roots=(root,),
    )

    with pytest.raises(ServiceUnavailableError, match="invalid endpoint credential"):
        service.enroll(
            token=grant_value(),
            csr_der=csr_for(ec.generate_private_key(ec.SECP256R1())),
            now=NOW,
        )
    assert store.fingerprint is not None
    assert store.activated is None


def test_enrollment_requires_a_pinned_issuer_root() -> None:
    root, root_key = issue_root()
    with pytest.raises(ValidationError, match="trust roots"):
        EnrollmentService(
            RecordingEnrollmentStore(),
            FakeIssuer(root, root_key),
            issuer_trust_roots=(),
        )


@pytest.mark.parametrize(
    "store_type",
    [FailingBeginStore, FailingRecordStore, RejectingRecordStore],
)
def test_enrollment_maps_database_outages_to_service_unavailable(
    store_type: type[RecordingEnrollmentStore],
) -> None:
    root, root_key = issue_root()
    service = EnrollmentService(
        store_type(),
        FakeIssuer(root, root_key),
        issuer_trust_roots=(root,),
    )

    with pytest.raises(ServiceUnavailableError, match="store is unavailable"):
        service.enroll(
            token=grant_value(),
            csr_der=csr_for(ec.generate_private_key(ec.SECP256R1())),
            now=NOW,
        )


def test_enrollment_application_returns_only_public_issued_material() -> None:
    operation = RecordingEnrollmentOperation()
    application = EnrollmentApplication(operation)
    body = json.dumps(
        {
            "grant": grant_value(),
            "csr": base64.b64encode(b"csr").decode("ascii"),
        },
        separators=(",", ":"),
    ).encode()

    response = application.handle(
        EnrollmentRequest(
            method="POST",
            path="/v1/enrollment",
            content_type="application/json",
            content_encoding=None,
            body=body,
        ),
        received_at=NOW,
    )

    assert response.status == 201
    assert response.headers == (
        ("content-type", "application/json"),
        ("cache-control", "no-store"),
    )
    assert json.loads(response.body) == {
        "endpoint_id": "11111111-1111-4111-8111-111111111111",
        "identity_id": "22222222-2222-4222-8222-222222222222",
        "state": "issued",
        "leaf_certificate": base64.b64encode(b"leaf").decode("ascii"),
        "intermediate_certificates": [
            base64.b64encode(b"intermediate").decode("ascii")
        ],
    }
    assert operation.calls == [(grant_value(), b"csr", NOW)]


@pytest.mark.parametrize(
    ("change", "value", "status"),
    [
        ("path", "/other", 404),
        ("method", "GET", 405),
        ("content_type", None, 415),
        ("content_encoding", "gzip", 415),
        ("body", b"", 413),
        ("body", b"{}", 400),
        ("body", b'{"grant":"x","grant":"y","csr":"eA=="}', 400),
        ("body", b'{"grant":"x","csr":"***"}', 400),
    ],
)
def test_enrollment_application_rejects_bad_http_and_json_contracts(
    change: str,
    value: object,
    status: int,
) -> None:
    operation = RecordingEnrollmentOperation()
    request_values: dict[str, object] = {
        "method": "POST",
        "path": "/v1/enrollment",
        "content_type": "application/json",
        "content_encoding": None,
        "body": b'{"grant":"x","csr":"eA=="}',
    }
    request_values[change] = value
    response = EnrollmentApplication(operation).handle(
        EnrollmentRequest(**request_values),  # type: ignore[arg-type]
        received_at=NOW,
    )

    assert response.status == status
    assert response.headers[1] == ("cache-control", "no-store")
    if status == 405:
        assert ("allow", "POST") in response.headers


@pytest.mark.parametrize(
    ("error", "status", "expected_body"),
    [
        (
            AuthorizationError("internal authorization detail"),
            403,
            "enrollment_unavailable",
        ),
        (
            ServiceUnavailableError("internal service detail"),
            503,
            "enrollment_unavailable",
        ),
        (ValidationError("internal validation detail"), 400, "invalid_enrollment"),
    ],
)
def test_enrollment_application_maps_expected_failures_generically(
    error: Exception,
    status: int,
    expected_body: str,
) -> None:
    operation = RecordingEnrollmentOperation(error=error)
    body = json.dumps(
        {"grant": grant_value(), "csr": base64.b64encode(b"csr").decode("ascii")}
    ).encode()
    response = EnrollmentApplication(operation).handle(
        EnrollmentRequest(
            method="POST",
            path="/v1/enrollment",
            content_type="application/json",
            content_encoding=None,
            body=body,
        ),
        received_at=NOW,
    )

    assert response.status == status
    assert json.loads(response.body) == {"error": expected_body}
    assert b"internal" not in response.body


@pytest.mark.parametrize(
    ("csr_der", "match"),
    [
        (b"", "size"),
        (b"not-der", "CSR is invalid"),
        (
            (
                x509.CertificateSigningRequestBuilder()
                .subject_name(x509.Name([]))
                .sign(ed25519.Ed25519PrivateKey.generate(), algorithm=None)
                .public_bytes(serialization.Encoding.DER)
            ),
            "public key is unsupported",
        ),
    ],
)
def test_enrollment_rejects_malformed_or_unsupported_csrs(
    csr_der: bytes,
    match: str,
) -> None:
    root, root_key = issue_root()
    store = RecordingEnrollmentStore()
    service = EnrollmentService(
        store,
        FakeIssuer(root, root_key),
        issuer_trust_roots=(root,),
    )

    with pytest.raises(ValidationError, match=match):
        service.enroll(token=grant_value(), csr_der=csr_der, now=NOW)
    assert store.fingerprint is None


def test_enrollment_normalizes_lazy_csr_decoding_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class LazyMalformedCsr:
        @property
        def is_signature_valid(self) -> bool:
            return True

        @property
        def subject(self) -> x509.Name:
            raise x509.DuplicateExtension(
                "duplicate extension",
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
            )

    monkeypatch.setattr(
        "northgate_rmm.enrollment.x509.load_der_x509_csr",
        lambda _encoded: LazyMalformedCsr(),
    )
    root, root_key = issue_root()
    store = RecordingEnrollmentStore()
    service = EnrollmentService(
        store,
        FakeIssuer(root, root_key),
        issuer_trust_roots=(root,),
    )

    with pytest.raises(ValidationError, match="CSR is invalid"):
        service.enroll(token=grant_value(), csr_der=b"signed", now=NOW)
    assert store.fingerprint is None


@pytest.mark.parametrize(
    "parser_error",
    [
        x509.InvalidVersion("invalid CSR version", 7),
        UnsupportedAlgorithm("unknown CSR public-key algorithm"),
    ],
)
def test_enrollment_normalizes_all_csr_parser_failures(
    monkeypatch: pytest.MonkeyPatch,
    parser_error: Exception,
) -> None:
    def reject_csr(_encoded: bytes) -> None:
        raise parser_error

    monkeypatch.setattr(
        "northgate_rmm.enrollment.x509.load_der_x509_csr",
        reject_csr,
    )
    root, root_key = issue_root()
    store = RecordingEnrollmentStore()
    service = EnrollmentService(
        store,
        FakeIssuer(root, root_key),
        issuer_trust_roots=(root,),
    )

    with pytest.raises(ValidationError, match="CSR is invalid"):
        service.enroll(token=grant_value(), csr_der=b"structured", now=NOW)
    assert store.fingerprint is None


def test_enrollment_rejects_invalid_issued_certificate_variants() -> None:
    trusted_root, _trusted_key = issue_root()
    untrusted_root, untrusted_key = issue_root()
    csr_der = csr_for(ec.generate_private_key(ec.SECP256R1()))
    template_store = RecordingEnrollmentStore()
    untrusted = FakeIssuer(untrusted_root, untrusted_key).issue_endpoint_certificate(
        EndpointIssuanceRequest(
            identity_id=template_store.identity_id,
            endpoint_id=template_store.endpoint_id,
            public_key_fingerprint="sha256:" + "0" * 64,
            csr_der=csr_der,
        ),
        now=NOW,
    )
    cases = (
        IssuedEndpointCredential(leaf_certificate_der=b"x" * 16_385),
        IssuedEndpointCredential(
            leaf_certificate_der=b"x",
            intermediate_certificates_der=(b"x",) * 5,
        ),
        IssuedEndpointCredential(leaf_certificate_der=b"not-der"),
        IssuedEndpointCredential(
            leaf_certificate_der=untrusted.leaf_certificate_der,
            intermediate_certificates_der=(b"",),
        ),
        untrusted,
    )
    for credential in cases:
        store = RecordingEnrollmentStore(
            endpoint_id=template_store.endpoint_id,
            identity_id=template_store.identity_id,
        )
        service = EnrollmentService(
            store,
            StaticIssuer(credential),
            issuer_trust_roots=(trusted_root,),
        )
        with pytest.raises(
            ServiceUnavailableError, match="invalid endpoint credential"
        ):
            service.enroll(token=grant_value(), csr_der=csr_der, now=NOW)
        assert store.activated is None


def csr_for(key: ec.EllipticCurvePrivateKey) -> bytes:
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([]))
        .sign(key, algorithm=hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )


def grant_value() -> str:
    return "ngr1_" + "x" * 43


def issue_root() -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Endpoint Root")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(ca_key_usage(), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, algorithm=hashes.SHA256())
    )
    return certificate, key


def endpoint_key_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


def ca_key_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )
