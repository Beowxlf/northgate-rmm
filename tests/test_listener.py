from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import socket
import ssl
import threading
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import NoReturn
from uuid import UUID, uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from northgate_rmm.domain import EndpointIdentity, HeartbeatMessage, InventoryMessage
from northgate_rmm.errors import ValidationError
from northgate_rmm.listener import (
    AgentListenerConfiguration,
    AgentTLSListener,
    build_server_ssl_context,
    create_agent_web_application,
    extract_verified_client_certificate,
)


@dataclass(frozen=True, slots=True)
class CertificateMaterial:
    root_certificate: x509.Certificate
    root_key: Ed25519PrivateKey
    server_certificate: x509.Certificate
    server_key: Ed25519PrivateKey
    client_certificate: x509.Certificate
    client_key: Ed25519PrivateKey
    endpoint_id: UUID


@dataclass
class RecordingStore:
    endpoint_id: UUID
    fingerprint: str
    identity_id: UUID = field(default_factory=uuid4)
    authentications: list[tuple[UUID, str]] = field(default_factory=list)
    inventories: list[InventoryMessage] = field(default_factory=list)

    def authenticate_endpoint_certificate(
        self,
        *,
        endpoint_id: UUID,
        public_key_fingerprint: str,
        authenticated_at: datetime,
        correlation_id: UUID,
    ) -> EndpointIdentity:
        del correlation_id
        assert authenticated_at.tzinfo is not None
        self.authentications.append((endpoint_id, public_key_fingerprint))
        if (
            endpoint_id != self.endpoint_id
            or public_key_fingerprint != self.fingerprint
        ):
            raise AssertionError("listener supplied incorrect certificate identity")
        return EndpointIdentity(
            identity_id=self.identity_id,
            endpoint_id=self.endpoint_id,
            public_key_fingerprint=self.fingerprint,
            created_at=authenticated_at,
        )

    def ingest_heartbeat(
        self,
        *,
        authenticated_identity_id: UUID,
        message: HeartbeatMessage,
        received_at: datetime,
        encoded_message_digest: str | None = None,
    ) -> NoReturn:
        del authenticated_identity_id, message, received_at, encoded_message_digest
        raise AssertionError("inventory request was routed as heartbeat")

    def ingest_inventory(
        self,
        *,
        authenticated_identity_id: UUID,
        message: InventoryMessage,
        received_at: datetime,
        encoded_message_digest: str | None = None,
    ) -> object:
        assert authenticated_identity_id == self.identity_id
        assert received_at.tzinfo is not None
        assert encoded_message_digest is not None
        self.inventories.append(message)
        return object()


@dataclass
class BlockingStore(RecordingStore):
    entered: threading.Event = field(default_factory=threading.Event)
    release: threading.Event = field(default_factory=threading.Event)

    def authenticate_endpoint_certificate(
        self,
        *,
        endpoint_id: UUID,
        public_key_fingerprint: str,
        authenticated_at: datetime,
        correlation_id: UUID,
    ) -> EndpointIdentity:
        self.entered.set()
        if not self.release.wait(timeout=5):
            raise AssertionError("test did not release the blocking store")
        return super().authenticate_endpoint_certificate(
            endpoint_id=endpoint_id,
            public_key_fingerprint=public_key_fingerprint,
            authenticated_at=authenticated_at,
            correlation_id=correlation_id,
        )


class SyntheticSSLObject:
    def __init__(self, certificate: x509.Certificate, version: str = "TLSv1.3") -> None:
        self._certificate = certificate
        self._version = version

    def version(self) -> str:
        return self._version

    def getpeercert(self, binary_form: bool = False) -> bytes | dict[str, object]:
        if not binary_form:
            return {}
        return self._certificate.public_bytes(serialization.Encoding.DER)


class EmptySSLObject:
    def version(self) -> str:
        return "TLSv1.3"

    def getpeercert(self, binary_form: bool = False) -> bytes | dict[str, object]:
        return b"" if binary_form else {}


def test_extract_verified_client_certificate_binds_uri_and_spki() -> None:
    material = issue_material(datetime.now(UTC))
    peer = extract_verified_client_certificate(
        SyntheticSSLObject(material.client_certificate)
    )
    expected = material.client_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    assert peer.endpoint_id == material.endpoint_id
    assert (
        peer.public_key_fingerprint == "sha256:" + hashlib.sha256(expected).hexdigest()
    )


def test_extract_verified_client_certificate_rejects_profile_variants() -> None:
    now = datetime.now(UTC)
    material = issue_material(now)
    with pytest.raises(ValidationError, match=r"TLS 1\.3"):
        extract_verified_client_certificate(
            SyntheticSSLObject(material.client_certificate, "TLSv1.2")
        )
    with pytest.raises(ValidationError, match="certificate is required"):
        extract_verified_client_certificate(EmptySSLObject())

    noncanonical = issue_client_certificate(
        material.root_certificate,
        material.root_key,
        material.client_key,
        now,
        [
            x509.UniformResourceIdentifier(
                "urn:northgate-rmm:endpoint:" + str(material.endpoint_id).upper()
            )
        ],
    )
    with pytest.raises(ValidationError, match="canonical"):
        extract_verified_client_certificate(SyntheticSSLObject(noncanonical))

    extra_name = issue_client_certificate(
        material.root_certificate,
        material.root_key,
        material.client_key,
        now,
        [
            x509.UniformResourceIdentifier(
                "urn:northgate-rmm:endpoint:" + str(material.endpoint_id)
            ),
            x509.DNSName("unexpected.invalid"),
        ],
    )
    with pytest.raises(ValidationError, match="endpoint identity"):
        extract_verified_client_certificate(SyntheticSSLObject(extra_name))

    with pytest.raises(ValidationError, match="profile"):
        extract_verified_client_certificate(
            SyntheticSSLObject(material.root_certificate)
        )
    with pytest.raises(ValidationError, match="extended purpose"):
        extract_verified_client_certificate(
            SyntheticSSLObject(material.server_certificate)
        )

    for endpoint_uri in (
        "urn:other:endpoint:" + str(material.endpoint_id),
        "urn:northgate-rmm:endpoint:not-a-uuid",
    ):
        invalid_uri = issue_client_certificate(
            material.root_certificate,
            material.root_key,
            material.client_key,
            now,
            [x509.UniformResourceIdentifier(endpoint_uri)],
        )
        with pytest.raises(ValidationError, match="endpoint identity"):
            extract_verified_client_certificate(SyntheticSSLObject(invalid_uri))

    ca_leaf = issue_leaf_certificate(
        material.root_certificate,
        material.root_key,
        material.client_key,
        now,
        ExtendedKeyUsageOID.CLIENT_AUTH,
        [
            x509.UniformResourceIdentifier(
                "urn:northgate-rmm:endpoint:" + str(material.endpoint_id)
            )
        ],
        is_ca=True,
    )
    with pytest.raises(ValidationError, match="purpose is invalid"):
        extract_verified_client_certificate(SyntheticSSLObject(ca_leaf))

    unknown_critical = issue_leaf_certificate(
        material.root_certificate,
        material.root_key,
        material.client_key,
        now,
        ExtendedKeyUsageOID.CLIENT_AUTH,
        [
            x509.UniformResourceIdentifier(
                "urn:northgate-rmm:endpoint:" + str(material.endpoint_id)
            )
        ],
        unknown_critical=True,
    )
    with pytest.raises(ValidationError, match="unknown critical"):
        extract_verified_client_certificate(SyntheticSSLObject(unknown_critical))

    unsupported_key = dsa.generate_private_key(key_size=2048)
    unsupported = issue_leaf_certificate(
        material.root_certificate,
        material.root_key,
        unsupported_key,
        now,
        ExtendedKeyUsageOID.CLIENT_AUTH,
        [
            x509.UniformResourceIdentifier(
                "urn:northgate-rmm:endpoint:" + str(material.endpoint_id)
            )
        ],
    )
    with pytest.raises(ValidationError, match="public key is unsupported"):
        extract_verified_client_certificate(SyntheticSSLObject(unsupported))


@pytest.mark.parametrize(
    ("change", "value", "match"),
    [
        ("bind_address", "not-an-ip", "IP literal"),
        ("bind_address", "8.8.8.8", "private"),
        ("port", -1, "port"),
        ("request_timeout_seconds", 0.5, "timeout"),
        ("authority", "RMM.TEST", "authority"),
        ("authority", "rmm.test:", "authority"),
        ("authority", "[::1]:", "authority"),
        ("authority", "rmm.test:99999", "authority"),
        ("authority", "-rmm.test", "authority"),
        ("authority", ":443", "authority"),
        ("authority", "rmm.test:0", "authority"),
        ("authority", "rmm.test.", "authority"),
    ],
)
def test_listener_configuration_rejects_ambiguous_values(
    tmp_path: Path,
    change: str,
    value: object,
    match: str,
) -> None:
    material = issue_material(datetime.now(UTC))
    paths = write_material(tmp_path, material)
    values: dict[str, object] = {
        "bind_address": "127.0.0.1",
        "port": 8443,
        "authority": "rmm.test",
        "server_certificate": paths["server_certificate"],
        "server_private_key": paths["server_private_key"],
        "endpoint_ca_certificate": paths["root_certificate"],
    }
    values[change] = value
    with pytest.raises(ValidationError, match=match):
        AgentListenerConfiguration(**values)  # type: ignore[arg-type]

    if change == "port":
        values["bind_address"] = "10.0.0.10"
        values["port"] = 0
        with pytest.raises(ValidationError, match="test-only"):
            AgentListenerConfiguration(**values)  # type: ignore[arg-type]


def test_listener_accepts_canonical_numeric_authority_and_rejects_bad_app_timeout(
    tmp_path: Path,
) -> None:
    material = issue_material(datetime.now(UTC))
    paths = write_material(tmp_path, material)
    configuration = listener_configuration(paths)
    AgentListenerConfiguration(
        bind_address="127.0.0.1",
        port=8443,
        authority="127.0.0.1:8443",
        server_certificate=configuration.server_certificate,
        server_private_key=configuration.server_private_key,
        endpoint_ca_certificate=configuration.endpoint_ca_certificate,
    )
    store = RecordingStore(material.endpoint_id, "sha256:" + "a" * 64)
    with pytest.raises(ValidationError, match="timeout"):
        create_agent_web_application(
            store,
            authority="rmm.test",
            request_timeout_seconds=0.5,
        )


def test_listener_start_cleans_up_after_tls_file_failure(tmp_path: Path) -> None:
    material = issue_material(datetime.now(UTC))
    paths = write_material(tmp_path, material)
    paths["server_certificate"] = tmp_path / "missing.pem"
    listener = AgentTLSListener(
        listener_configuration(paths),
        RecordingStore(material.endpoint_id, "sha256:" + "a" * 64),
    )

    async def scenario() -> None:
        with pytest.raises(ValidationError, match="real file"):
            await listener.start()
        assert len(listener.addresses) == 0

    asyncio.run(scenario())


def test_listener_configuration_and_tls_context_fail_closed(tmp_path: Path) -> None:
    material = issue_material(datetime.now(UTC))
    paths = write_material(tmp_path, material)
    configuration = listener_configuration(paths)
    context = build_server_ssl_context(configuration)

    assert context.minimum_version == ssl.TLSVersion.TLSv1_3
    assert context.maximum_version == ssl.TLSVersion.TLSv1_3
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.num_tickets == 0

    with pytest.raises(ValidationError, match="wildcard"):
        listener_configuration(paths, bind_address="0.0.0.0")  # noqa: S104
    with pytest.raises(ValidationError, match="real file"):
        build_server_ssl_context(
            listener_configuration(
                paths | {"server_certificate": tmp_path / "missing.pem"}
            )
        )


def test_real_listener_accepts_only_profiled_mtls_messages(tmp_path: Path) -> None:
    asyncio.run(run_listener_scenario(tmp_path))


def test_listener_bounds_headers_body_readers_and_store_time(tmp_path: Path) -> None:
    asyncio.run(run_listener_deadline_scenario(tmp_path))


def test_listener_rate_limits_one_authenticated_identity(tmp_path: Path) -> None:
    asyncio.run(run_listener_rate_limit_scenario(tmp_path))


def test_listener_rebinds_fixed_port_after_force_closed_request(tmp_path: Path) -> None:
    asyncio.run(run_listener_restart_scenario(tmp_path))


def test_listener_rejects_pipelined_requests(tmp_path: Path) -> None:
    asyncio.run(run_listener_pipeline_scenario(tmp_path))


async def run_listener_scenario(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    material = issue_material(now)
    paths = write_material(tmp_path, material)
    fingerprint = public_key_fingerprint(material.client_key.public_key())
    store = RecordingStore(material.endpoint_id, fingerprint)
    listener = AgentTLSListener(listener_configuration(paths), store)
    await listener.start()
    try:
        with pytest.raises(RuntimeError, match="already started"):
            await listener.start()
        assert len(listener.addresses) == 1
        host, port = listener.addresses[0]
        client_context = client_ssl_context(paths)
        body = inventory_body(material.endpoint_id, now)
        response = await raw_https_request(
            host,
            port,
            client_context,
            request_bytes(body),
        )

        assert response.startswith(b"HTTP/1.1 200 OK\r\n")
        assert b"\r\nServer:" not in response
        assert b"X-Content-Type-Options: nosniff\r\n" in response
        assert json.loads(response.split(b"\r\n\r\n", 1)[1])["accepted"] is True
        assert store.authentications == [(material.endpoint_id, fingerprint)]
        assert len(store.inventories) == 1

        wrong_host = await raw_https_request(
            host,
            port,
            client_context,
            request_bytes(body, authority="other.invalid"),
        )
        duplicate_type = await raw_https_request(
            host,
            port,
            client_context,
            request_bytes(body, duplicate_content_type=True),
        )
        assert wrong_host.startswith(b"HTTP/1.1 421 Misdirected Request\r\n")
        assert duplicate_type.startswith(b"HTTP/1.0 400 Bad Request\r\n")
        assert b"\r\nServer:" not in duplicate_type
        assert duplicate_type.endswith(b'{"error":"invalid_request"}')

        http10 = await raw_https_request(
            host,
            port,
            client_context,
            request_bytes(body, http_version="HTTP/1.0"),
        )
        encoded = await raw_https_request(
            host,
            port,
            client_context,
            request_bytes(body, content_encoding="gzip"),
        )
        oversized = await raw_https_request(
            host,
            port,
            client_context,
            request_bytes(b"x" * 65_537),
        )
        assert http10.startswith(b"HTTP/1.0 505 HTTP Version Not Supported\r\n")
        assert encoded.startswith(b"HTTP/1.1 415 Unsupported Media Type\r\n")
        assert oversized.startswith(b"HTTP/1.1 413 Request Entity Too Large\r\n")

        invalid_profile = issue_client_certificate(
            material.root_certificate,
            material.root_key,
            material.client_key,
            now,
            [
                x509.UniformResourceIdentifier(
                    "urn:northgate-rmm:endpoint:" + str(material.endpoint_id)
                ),
                x509.DNSName("unexpected.invalid"),
            ],
        )
        paths["client_certificate"].write_bytes(
            invalid_profile.public_bytes(serialization.Encoding.PEM)
        )
        profile_context = client_ssl_context(paths)
        with pytest.raises(ConnectionError):
            await raw_https_request(
                host,
                port,
                profile_context,
                request_bytes(body),
            )

        no_identity = ssl.create_default_context(cafile=str(paths["root_certificate"]))
        no_identity.minimum_version = ssl.TLSVersion.TLSv1_3
        no_identity.maximum_version = ssl.TLSVersion.TLSv1_3
        with pytest.raises((ConnectionError, OSError, ssl.SSLError)):
            await raw_https_request(host, port, no_identity, request_bytes(body))

        tls12 = client_ssl_context(paths)
        tls12.minimum_version = ssl.TLSVersion.TLSv1_2
        tls12.maximum_version = ssl.TLSVersion.TLSv1_2
        with pytest.raises((ConnectionError, OSError, ssl.SSLError)):
            await raw_https_request(host, port, tls12, request_bytes(body))
    finally:
        await listener.close()
        await listener.close()
    assert len(listener.addresses) == 0


async def run_listener_deadline_scenario(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    material = issue_material(now)
    paths = write_material(tmp_path, material)
    fingerprint = public_key_fingerprint(material.client_key.public_key())
    store = RecordingStore(material.endpoint_id, fingerprint)
    listener = AgentTLSListener(
        listener_configuration(paths, request_timeout_seconds=1.0), store
    )
    await listener.start()
    partial_connections: list[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = []
    try:
        host, port = listener.addresses[0]
        client_context = client_ssl_context(paths)

        handshake_reader, handshake_writer = await asyncio.open_connection(host, port)
        assert await asyncio.wait_for(handshake_reader.read(), timeout=2) == b""
        handshake_writer.close()
        await handshake_writer.wait_closed()

        header_reader, header_writer = await open_https_connection(
            host, port, client_context
        )
        header_writer.write(b"POST /v1/agent/messages HTTP/1.1\r\nHost: rmm.test")
        await header_writer.drain()
        assert await asyncio.wait_for(header_reader.read(), timeout=2) == b""
        header_writer.close()
        await header_writer.wait_closed()

        for _ in range(4):
            reader, writer = await open_https_connection(host, port, client_context)
            writer.write(
                b"POST /v1/agent/messages HTTP/1.1\r\n"
                b"Host: rmm.test\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: 1\r\n"
                b"Connection: close\r\n\r\n"
            )
            await writer.drain()
            partial_connections.append((reader, writer))
        await asyncio.sleep(0.1)
        with pytest.raises(ConnectionError):
            await raw_https_request(
                host,
                port,
                client_context,
                request_bytes(inventory_body(material.endpoint_id, now)),
            )
    finally:
        for _reader, writer in partial_connections:
            writer.close()
        await asyncio.gather(
            *(writer.wait_closed() for _reader, writer in partial_connections),
            return_exceptions=True,
        )
        await listener.close()

    blocking_store = BlockingStore(material.endpoint_id, fingerprint)
    blocking_listener = AgentTLSListener(
        listener_configuration(paths, request_timeout_seconds=1.0), blocking_store
    )
    await blocking_listener.start()
    try:
        host, port = blocking_listener.addresses[0]
        response = await raw_https_request(
            host,
            port,
            client_ssl_context(paths),
            request_bytes(inventory_body(material.endpoint_id, datetime.now(UTC))),
        )
        assert blocking_store.entered.is_set()
        assert response.startswith(b"HTTP/1.1 408 Request Timeout\r\n")
    finally:
        blocking_store.release.set()
        await asyncio.sleep(0.05)
        await blocking_listener.close()


async def run_listener_rate_limit_scenario(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    material = issue_material(now)
    paths = write_material(tmp_path, material)
    fingerprint = public_key_fingerprint(material.client_key.public_key())
    store = RecordingStore(material.endpoint_id, fingerprint)
    listener = AgentTLSListener(listener_configuration(paths), store)
    await listener.start()
    try:
        host, port = listener.addresses[0]
        client_context = client_ssl_context(paths)
        request = request_bytes(inventory_body(material.endpoint_id, now))
        responses = [
            await raw_https_request(host, port, client_context, request)
            for _ in range(33)
        ]
        assert all(
            response.startswith(b"HTTP/1.1 200 OK\r\n") for response in responses[:32]
        )
        assert responses[32].startswith(b"HTTP/1.1 429 Too Many Requests\r\n")
        assert len(store.authentications) == 32
        assert len(store.inventories) == 32
    finally:
        await listener.close()


async def run_listener_restart_scenario(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    material = issue_material(now)
    paths = write_material(tmp_path, material)
    fingerprint = public_key_fingerprint(material.client_key.public_key())
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    configuration = replace(listener_configuration(paths), port=port)

    for _ in range(2):
        listener = AgentTLSListener(
            configuration, RecordingStore(material.endpoint_id, fingerprint)
        )
        await listener.start()
        try:
            response = await raw_https_request(
                "127.0.0.1",
                port,
                client_ssl_context(paths),
                request_bytes(inventory_body(material.endpoint_id, datetime.now(UTC))),
            )
            assert response.startswith(b"HTTP/1.1 200 OK\r\n")
        finally:
            await listener.close()


async def run_listener_pipeline_scenario(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    material = issue_material(now)
    paths = write_material(tmp_path, material)
    fingerprint = public_key_fingerprint(material.client_key.public_key())
    store = RecordingStore(material.endpoint_id, fingerprint)
    listener = AgentTLSListener(listener_configuration(paths), store)
    await listener.start()
    try:
        host, port = listener.addresses[0]
        context = client_ssl_context(paths)
        first = request_bytes(inventory_body(material.endpoint_id, now))
        second = request_bytes(inventory_body(material.endpoint_id, now))
        with contextlib.suppress(ConnectionError):
            await raw_https_request(host, port, context, first + second)
        await asyncio.sleep(0.05)
        assert len(store.inventories) <= 1

        accepted_before = len(store.inventories)
        response = await raw_https_request(
            host,
            port,
            context,
            request_bytes(inventory_body(material.endpoint_id, datetime.now(UTC))),
        )
        assert response.startswith(b"HTTP/1.1 200 OK\r\n")
        assert len(store.inventories) == accepted_before + 1
    finally:
        await listener.close()


def issue_material(now: datetime) -> CertificateMaterial:
    root_key = Ed25519PrivateKey.generate()
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Listener Test CA")])
    root_certificate = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(ca_key_usage(), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, algorithm=None)
    )
    server_key = Ed25519PrivateKey.generate()
    server_certificate = issue_leaf_certificate(
        root_certificate,
        root_key,
        server_key,
        now,
        ExtendedKeyUsageOID.SERVER_AUTH,
        [x509.DNSName("rmm.test")],
    )
    endpoint_id = uuid4()
    client_key = Ed25519PrivateKey.generate()
    client_certificate = issue_client_certificate(
        root_certificate,
        root_key,
        client_key,
        now,
        [
            x509.UniformResourceIdentifier(
                "urn:northgate-rmm:endpoint:" + str(endpoint_id)
            )
        ],
    )
    return CertificateMaterial(
        root_certificate=root_certificate,
        root_key=root_key,
        server_certificate=server_certificate,
        server_key=server_key,
        client_certificate=client_certificate,
        client_key=client_key,
        endpoint_id=endpoint_id,
    )


def issue_client_certificate(
    root_certificate: x509.Certificate,
    root_key: Ed25519PrivateKey,
    client_key: Ed25519PrivateKey,
    now: datetime,
    names: list[x509.GeneralName],
) -> x509.Certificate:
    return issue_leaf_certificate(
        root_certificate,
        root_key,
        client_key,
        now,
        ExtendedKeyUsageOID.CLIENT_AUTH,
        names,
    )


def issue_leaf_certificate(
    root_certificate: x509.Certificate,
    root_key: Ed25519PrivateKey,
    leaf_key: Ed25519PrivateKey | dsa.DSAPrivateKey,
    now: datetime,
    purpose: x509.ObjectIdentifier,
    names: list[x509.GeneralName],
    *,
    is_ca: bool = False,
    unknown_critical: bool = False,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-leaf")]))
        .issuer_name(root_certificate.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=30))
        .add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=0 if is_ca else None),
            critical=True,
        )
        .add_extension(leaf_key_usage(), critical=True)
        .add_extension(x509.ExtendedKeyUsage([purpose]), critical=True)
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
    )
    if unknown_critical:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier("1.3.6.1.4.1.55555.1"), b"\x05\x00"
            ),
            critical=True,
        )
    return builder.sign(root_key, algorithm=None)


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


def leaf_key_usage() -> x509.KeyUsage:
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


def write_material(tmp_path: Path, material: CertificateMaterial) -> dict[str, Path]:
    paths = {
        "root_certificate": tmp_path / "root.pem",
        "server_certificate": tmp_path / "server.pem",
        "server_private_key": tmp_path / "server-key.pem",
        "client_certificate": tmp_path / "client.pem",
        "client_private_key": tmp_path / "client-key.pem",
    }
    paths["root_certificate"].write_bytes(
        material.root_certificate.public_bytes(serialization.Encoding.PEM)
    )
    paths["server_certificate"].write_bytes(
        material.server_certificate.public_bytes(serialization.Encoding.PEM)
    )
    paths["server_private_key"].write_bytes(private_key_bytes(material.server_key))
    paths["client_certificate"].write_bytes(
        material.client_certificate.public_bytes(serialization.Encoding.PEM)
    )
    paths["client_private_key"].write_bytes(private_key_bytes(material.client_key))
    return paths


def private_key_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def listener_configuration(
    paths: dict[str, Path],
    *,
    bind_address: str = "127.0.0.1",
    request_timeout_seconds: float = 10.0,
) -> AgentListenerConfiguration:
    return AgentListenerConfiguration(
        bind_address=bind_address,
        port=0,
        authority="rmm.test",
        server_certificate=paths["server_certificate"],
        server_private_key=paths["server_private_key"],
        endpoint_ca_certificate=paths["root_certificate"],
        request_timeout_seconds=request_timeout_seconds,
    )


def client_ssl_context(paths: dict[str, Path]) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=str(paths["root_certificate"]))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(
        certfile=paths["client_certificate"],
        keyfile=paths["client_private_key"],
    )
    return context


def inventory_body(endpoint_id: UUID, now: datetime) -> bytes:
    return json.dumps(
        {
            "type": "inventory",
            "envelope": {
                "message_id": str(uuid4()),
                "endpoint_id": str(endpoint_id),
                "boot_id": str(uuid4()),
                "sequence": 1,
                "created_at": now.isoformat(),
                "expires_at": (now + timedelta(minutes=1)).isoformat(),
                "correlation_id": str(uuid4()),
                "protocol_version": 1,
            },
            "payload": {
                "platform": "linux",
                "architecture": "amd64",
                "fields": {"os.id": "debian", "os.version_id": "12"},
                "collector_complete": True,
                "schema_version": 1,
            },
        },
        separators=(",", ":"),
    ).encode()


def request_bytes(
    body: bytes,
    *,
    authority: str = "rmm.test",
    duplicate_content_type: bool = False,
    content_encoding: str | None = None,
    http_version: str = "HTTP/1.1",
) -> bytes:
    content_types = b"Content-Type: application/json\r\n"
    if duplicate_content_type:
        content_types += b"Content-Type: application/json\r\n"
    encoding = (
        b""
        if content_encoding is None
        else f"Content-Encoding: {content_encoding}\r\n".encode()
    )
    return (
        f"POST /v1/agent/messages {http_version}\r\n".encode()
        + f"Host: {authority}\r\n".encode()
        + content_types
        + encoding
        + f"Content-Length: {len(body)}\r\n".encode()
        + b"Connection: close\r\n\r\n"
        + body
    )


async def raw_https_request(
    host: str,
    port: int,
    context: ssl.SSLContext,
    request: bytes,
) -> bytes:
    reader, writer = await open_https_connection(host, port, context)
    try:
        writer.write(request)
        await writer.drain()
        response = await asyncio.wait_for(reader.read(), timeout=5)
        if not response:
            raise ConnectionError("listener closed without an HTTP response")
        return response
    finally:
        writer.close()
        await writer.wait_closed()


async def open_https_connection(
    host: str,
    port: int,
    context: ssl.SSLContext,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.open_connection(
        host,
        port,
        ssl=context,
        server_hostname="rmm.test",
    )


def public_key_fingerprint(key: Ed25519PublicKey) -> str:
    encoded = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "sha256:" + hashlib.sha256(encoded).hexdigest()
