"""Proof-of-possession enrollment orchestration with an external issuer boundary.

The control plane validates a locally generated CSR, atomically consumes a
single-use grant into a pending identity, and asks a separate issuer for the
endpoint certificate. This module accepts issued public certificates only; it
has no CA private-key input or signing primitive.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol, cast
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from northgate_rmm.domain import Endpoint, EndpointIdentity, require_aware
from northgate_rmm.errors import AuthorizationError, ValidationError
from northgate_rmm.listener import validate_endpoint_certificate

MAX_CSR_BYTES = 8_192
MAX_CERTIFICATE_BYTES = 16_384
MAX_INTERMEDIATE_CERTIFICATES = 4
MAX_ENROLLMENT_BODY_BYTES = 16_384
ENROLLMENT_PATH = "/v1/enrollment"


@dataclass(frozen=True, slots=True)
class EndpointIssuanceRequest:
    """Public facts sent to an issuer using the identity ID as idempotency key."""

    identity_id: UUID
    endpoint_id: UUID
    public_key_fingerprint: str
    csr_der: bytes


@dataclass(frozen=True, slots=True)
class IssuedEndpointCredential:
    """Public certificate material returned by the separate endpoint issuer."""

    leaf_certificate_der: bytes
    intermediate_certificates_der: tuple[bytes, ...] = ()


@dataclass(frozen=True, slots=True)
class EnrollmentResult:
    endpoint_id: UUID
    identity_id: UUID
    leaf_certificate_der: bytes
    intermediate_certificates_der: tuple[bytes, ...]


@dataclass(frozen=True, slots=True)
class EnrollmentRequest:
    method: str
    path: str
    content_type: str | None
    content_encoding: str | None
    body: bytes


@dataclass(frozen=True, slots=True)
class EnrollmentResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


class EnrollmentStore(Protocol):
    def begin_endpoint_enrollment(
        self,
        *,
        token: str,
        public_key_fingerprint: str,
        now: datetime,
        actor_id: str = "enrollment-service",
    ) -> tuple[Endpoint, EndpointIdentity]: ...

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
    ) -> EndpointIdentity: ...


class EndpointCertificateIssuer(Protocol):
    def issue_endpoint_certificate(
        self,
        request: EndpointIssuanceRequest,
        *,
        now: datetime,
    ) -> IssuedEndpointCredential: ...


class EnrollmentOperation(Protocol):
    def enroll(
        self,
        *,
        token: str,
        csr_der: bytes,
        now: datetime,
    ) -> EnrollmentResult: ...


class EnrollmentApplication:
    """Bounded in-process HTTP contract for server-authenticated enrollment."""

    def __init__(self, operation: EnrollmentOperation) -> None:
        self._operation = operation

    def handle(
        self,
        request: EnrollmentRequest,
        *,
        received_at: datetime,
    ) -> EnrollmentResponse:
        if request.path != ENROLLMENT_PATH:
            return _http_error(404, "not_found")
        if request.method != "POST":
            return _http_error(405, "method_not_allowed", allow="POST")
        if request.content_type is None or request.content_type.lower() != (
            "application/json"
        ):
            return _http_error(415, "unsupported_media_type")
        if request.content_encoding is not None:
            return _http_error(415, "content_encoding_not_allowed")
        if not request.body or len(request.body) > MAX_ENROLLMENT_BODY_BYTES:
            return _http_error(413, "request_size_invalid")
        try:
            token, csr_der = _decode_enrollment_body(request.body)
            result = self._operation.enroll(
                token=token,
                csr_der=csr_der,
                now=received_at,
            )
        except AuthorizationError:
            return _http_error(403, "enrollment_unavailable")
        except ValidationError:
            return _http_error(400, "invalid_enrollment")
        return _http_json(
            201,
            {
                "endpoint_id": str(result.endpoint_id),
                "identity_id": str(result.identity_id),
                "state": "issued",
                "leaf_certificate": base64.b64encode(
                    result.leaf_certificate_der
                ).decode("ascii"),
                "intermediate_certificates": [
                    base64.b64encode(certificate).decode("ascii")
                    for certificate in result.intermediate_certificates_der
                ],
            },
        )


class EnrollmentService:
    """Turn one grant and CSR into a validated, issued endpoint credential."""

    def __init__(
        self,
        store: EnrollmentStore,
        issuer: EndpointCertificateIssuer,
        *,
        issuer_trust_roots: tuple[x509.Certificate, ...],
    ) -> None:
        if not issuer_trust_roots:
            raise ValidationError("endpoint issuer trust roots are required")
        self._store = store
        self._issuer = issuer
        self._issuer_store = Store(list(issuer_trust_roots))

    def enroll(self, *, token: str, csr_der: bytes, now: datetime) -> EnrollmentResult:
        require_aware(now, "now")
        server_time = now.astimezone(UTC)
        canonical_csr, fingerprint = _validate_csr(csr_der)
        endpoint, identity = self._store.begin_endpoint_enrollment(
            token=token,
            public_key_fingerprint=fingerprint,
            now=server_time,
        )
        issued = self._issuer.issue_endpoint_certificate(
            EndpointIssuanceRequest(
                identity_id=identity.identity_id,
                endpoint_id=endpoint.endpoint_id,
                public_key_fingerprint=fingerprint,
                csr_der=canonical_csr,
            ),
            now=server_time,
        )
        leaf, intermediates = self._validate_issued_credential(
            issued,
            endpoint_id=endpoint.endpoint_id,
            public_key_fingerprint=fingerprint,
            now=server_time,
        )
        self._store.record_issued_endpoint_identity(
            identity.identity_id,
            certificate_serial=format(leaf.serial_number, "x"),
            certificate_issuer=leaf.issuer.rfc4514_string(),
            certificate_not_before=leaf.not_valid_before_utc,
            certificate_not_after=leaf.not_valid_after_utc,
            now=server_time,
        )
        return EnrollmentResult(
            endpoint_id=endpoint.endpoint_id,
            identity_id=identity.identity_id,
            leaf_certificate_der=leaf.public_bytes(serialization.Encoding.DER),
            intermediate_certificates_der=tuple(
                certificate.public_bytes(serialization.Encoding.DER)
                for certificate in intermediates
            ),
        )

    def _validate_issued_credential(
        self,
        issued: IssuedEndpointCredential,
        *,
        endpoint_id: UUID,
        public_key_fingerprint: str,
        now: datetime,
    ) -> tuple[x509.Certificate, tuple[x509.Certificate, ...]]:
        if not 1 <= len(issued.leaf_certificate_der) <= MAX_CERTIFICATE_BYTES:
            raise ValidationError("issued endpoint certificate size is invalid")
        if len(issued.intermediate_certificates_der) > MAX_INTERMEDIATE_CERTIFICATES:
            raise ValidationError("issued endpoint chain is too long")
        try:
            leaf = x509.load_der_x509_certificate(issued.leaf_certificate_der)
            intermediates = tuple(
                x509.load_der_x509_certificate(encoded)
                for encoded in issued.intermediate_certificates_der
                if 1 <= len(encoded) <= MAX_CERTIFICATE_BYTES
            )
        except ValueError as error:
            raise ValidationError("issued endpoint certificate is invalid") from error
        if len(intermediates) != len(issued.intermediate_certificates_der):
            raise ValidationError("issued endpoint certificate size is invalid")
        try:
            (
                PolicyBuilder()
                .store(self._issuer_store)
                .time(now)
                .build_client_verifier()
                .verify(leaf, list(intermediates))
            )
        except VerificationError as error:
            raise ValidationError(
                "issued endpoint certificate chain is invalid"
            ) from error
        peer = validate_endpoint_certificate(leaf)
        if (
            peer.endpoint_id != endpoint_id
            or peer.public_key_fingerprint != public_key_fingerprint
        ):
            raise ValidationError("issued endpoint certificate binding is invalid")
        if not leaf.not_valid_before_utc <= now < leaf.not_valid_after_utc:
            raise ValidationError("issued endpoint certificate is not currently valid")
        return leaf, intermediates


def _decode_enrollment_body(raw: bytes) -> tuple[str, bytes]:
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValidationError("enrollment body is invalid JSON") from error
    if not isinstance(value, dict):
        raise ValidationError("enrollment body must be an object")
    body = cast(dict[str, Any], value)
    if set(body) != {"grant", "csr"}:
        raise ValidationError("enrollment body fields do not match the schema")
    token = body["grant"]
    encoded_csr = body["csr"]
    if not isinstance(token, str) or not 1 <= len(token) <= 128:
        raise ValidationError("enrollment grant is invalid")
    if not isinstance(encoded_csr, str) or not 1 <= len(encoded_csr) <= 12_000:
        raise ValidationError("endpoint CSR encoding is invalid")
    try:
        csr_der = base64.b64decode(encoded_csr, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValidationError("endpoint CSR encoding is invalid") from error
    return token, csr_der


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValidationError("enrollment body contains a duplicate field")
        value[key] = item
    return value


def _reject_json_constant(_raw: str) -> None:
    raise ValidationError("enrollment body contains a non-finite value")


def _http_error(
    status: int,
    code: str,
    *,
    allow: str | None = None,
) -> EnrollmentResponse:
    response = _http_json(status, {"error": code})
    if allow is None:
        return response
    return EnrollmentResponse(
        status=response.status,
        headers=(*response.headers, ("allow", allow)),
        body=response.body,
    )


def _http_json(status: int, value: dict[str, object]) -> EnrollmentResponse:
    return EnrollmentResponse(
        status=status,
        headers=(
            ("content-type", "application/json"),
            ("cache-control", "no-store"),
        ),
        body=json.dumps(value, separators=(",", ":")).encode("ascii"),
    )


def _validate_csr(csr_der: bytes) -> tuple[bytes, str]:
    if not 1 <= len(csr_der) <= MAX_CSR_BYTES:
        raise ValidationError("endpoint CSR size is invalid")
    try:
        csr = x509.load_der_x509_csr(csr_der)
        if not csr.is_signature_valid:
            raise ValidationError("endpoint CSR proof of possession is invalid")
        if (
            len(csr.subject) != 0
            or len(csr.extensions) != 0
            or len(csr.attributes) != 0
        ):
            raise ValidationError("endpoint CSR contains unauthorized claims")
        public_key = csr.public_key()
        if not _supported_public_key(public_key):
            raise ValidationError("endpoint CSR public key is unsupported")
        subject_public_key = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        canonical_csr = csr.public_bytes(serialization.Encoding.DER)
    except (ValueError, x509.DuplicateExtension) as error:
        raise ValidationError("endpoint CSR is invalid") from error
    return canonical_csr, "sha256:" + hashlib.sha256(subject_public_key).hexdigest()


def _supported_public_key(key: object) -> bool:
    if isinstance(key, ec.EllipticCurvePublicKey):
        return isinstance(key.curve, (ec.SECP256R1, ec.SECP384R1))
    return isinstance(key, rsa.RSAPublicKey) and key.key_size >= 2_048
