"""Same-key certificate renewal over the existing authenticated agent boundary."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid5

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from psycopg.types.json import Jsonb

from northgate_rmm.agent_api import VerifiedClientCertificate
from northgate_rmm.enrollment import (
    EndpointCertificateIssuer,
    EndpointIssuanceRequest,
    EnrollmentService,
    _validate_csr,
)
from northgate_rmm.errors import AuthorizationError, ValidationError
from northgate_rmm.persistence import PostgresControlPlane
from northgate_rmm.workload_service import strict_object


class RenewalService:
    def __init__(
        self,
        store: PostgresControlPlane,
        issuer: EndpointCertificateIssuer,
        trust_root: x509.Certificate,
    ) -> None:
        self.store, self.issuer = store, issuer
        self.validator = EnrollmentService(
            store, issuer, issuer_trust_roots=(trust_root,)
        )

    def renew(
        self, body: bytes, peer: VerifiedClientCertificate, now: datetime
    ) -> dict[str, Any]:
        request = strict_object(body, maximum=16384)
        if set(request) != {"request_id", "csr"}:
            raise ValidationError("renewal fields invalid")
        request_id = UUID(request["request_id"])
        if str(request_id) != request["request_id"]:
            raise ValidationError("renewal request ID invalid")
        csr, fingerprint = _validate_csr(
            base64.b64decode(request["csr"], validate=True)
        )
        if fingerprint != peer.public_key_fingerprint:
            raise AuthorizationError("renewal must prove the authenticated key")
        identity = self.store.authenticate_endpoint_certificate(
            endpoint_id=peer.endpoint_id,
            public_key_fingerprint=fingerprint,
            authenticated_at=now,
            correlation_id=request_id,
        )
        with self.store._connect() as db, db.cursor() as cursor:
            cursor.execute(
                "SELECT response FROM certificate_renewals WHERE request_id=%s AND "
                "identity_id=%s",
                (request_id, identity.identity_id),
            )
            previous = cursor.fetchone()
            if previous is not None:
                return dict(previous["response"])
            cursor.execute(
                "SELECT certificate_not_after FROM endpoint_identities WHERE "
                "identity_id=%s",
                (identity.identity_id,),
            )
            row = cursor.fetchone()
            if (
                row is None
                or row["certificate_not_after"] is None
                or row["certificate_not_after"] > now + timedelta(hours=6)
            ):
                raise AuthorizationError("renewal is outside its window")
        issued = self.issuer.issue_endpoint_certificate(
            EndpointIssuanceRequest(
                identity_id=uuid5(identity.identity_id, str(request_id)),
                endpoint_id=peer.endpoint_id,
                public_key_fingerprint=fingerprint,
                csr_der=csr,
            ),
            now=now,
        )
        leaf, intermediates = self.validator._validate_issued_credential(
            issued,
            endpoint_id=peer.endpoint_id,
            public_key_fingerprint=fingerprint,
            now=now,
        )
        if leaf.not_valid_after_utc - leaf.not_valid_before_utc > timedelta(hours=24):
            raise ValidationError("renewed certificate exceeds maximum lifetime")
        result = {
            "endpoint_id": str(peer.endpoint_id),
            "identity_id": str(identity.identity_id),
            "state": "issued",
            "leaf_certificate": base64.b64encode(
                leaf.public_bytes(serialization.Encoding.DER)
            ).decode("ascii"),
            "intermediate_certificates": [
                base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode(
                    "ascii"
                )
                for cert in intermediates
            ],
        }
        with self.store._connect() as db, db.cursor() as cursor:
            cursor.execute(
                "SELECT i.identity_status, i.revoked_at, i.certificate_not_after, "
                "e.identity_id AS current_identity FROM endpoint_identities i JOIN "
                "endpoints e ON e.endpoint_id=i.endpoint_id WHERE i.identity_id=%s "
                "FOR UPDATE OF i,e",
                (identity.identity_id,),
            )
            row = cursor.fetchone()
            if (
                row is None
                or row["revoked_at"] is not None
                or row["identity_status"] not in {"issued", "active"}
                or row["current_identity"] != identity.identity_id
            ):
                raise AuthorizationError("renewal identity no longer current")
            cursor.execute(
                "SELECT response FROM certificate_renewals WHERE request_id=%s AND "
                "identity_id=%s",
                (request_id, identity.identity_id),
            )
            previous = cursor.fetchone()
            if previous is not None:
                return dict(previous["response"])
            if row["certificate_not_after"] > now + timedelta(hours=6):
                raise AuthorizationError("another renewal already completed")
            cursor.execute(
                "UPDATE endpoint_identities SET "
                "certificate_serial=%s,certificate_issuer=%s,"
                "certificate_not_before=%s,certificate_not_after=%s "
                "WHERE identity_id=%s",
                (
                    format(leaf.serial_number, "x"),
                    leaf.issuer.rfc4514_string(),
                    leaf.not_valid_before_utc,
                    leaf.not_valid_after_utc,
                    identity.identity_id,
                ),
            )
            cursor.execute(
                "INSERT INTO "
                "certificate_renewals(request_id,identity_id,response,created_at) "
                "VALUES(%s,%s,%s,%s)",
                (request_id, identity.identity_id, Jsonb(result), now),
            )
            self.store._insert_audit(
                cursor,
                server_time=now,
                actor_type="endpoint_certificate",
                actor_id=str(identity.identity_id),
                subject=f"endpoint:{peer.endpoint_id}",
                action="certificate.renew",
                decision="accepted",
                reason="authenticated same-key renewal",
                correlation_id=request_id,
            )
        return result
