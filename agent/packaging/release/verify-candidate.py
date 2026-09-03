#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys
from typing import Any


class VerificationError(Exception):
    pass


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"invalid JSON in {path.name}: {error}") from error
    if not isinstance(value, dict):
        raise VerificationError(f"{path.name} must contain a JSON object")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def evidence_path(root: pathlib.Path, record: Any, label: str) -> pathlib.Path:
    require(isinstance(record, dict), f"{label} evidence must be an object")
    name = record.get("path")
    require(isinstance(name, str), f"{label} path must be a string")
    require(name not in {"", ".", ".."}, f"{label} path is invalid")
    require("/" not in name and "\\" not in name, f"{label} path must be a filename")
    path = root / name
    require(path.is_file() and not path.is_symlink(), f"{label} file is missing or unsafe")
    require(record.get("sha256") == digest(path), f"{label} SHA-256 mismatch")
    require(record.get("size") == path.stat().st_size, f"{label} size mismatch")
    return path


def dpkg_field(package: pathlib.Path, field: str) -> str:
    try:
        process = subprocess.run(
            ["dpkg-deb", "--field", str(package), field],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise VerificationError(f"cannot inspect package field {field}") from error
    return process.stdout.strip()


def verify(
    root: pathlib.Path,
    expected_commit: str,
    expected_version: str,
    expected_package_sha256: str,
    expected_source_date_epoch: int,
    expected_public_key_sha256: str,
    expected_invocation_id: str,
    cosign: str,
    spdx_schema: pathlib.Path,
    spdx_validator: pathlib.Path,
) -> dict[str, Any]:
    require(root.is_dir(), "candidate directory is missing")
    require(bool(re.fullmatch(r"[0-9a-f]{40}", expected_commit)), "expected commit must be a full SHA")
    require(bool(re.fullmatch(r"[0-9A-Za-z.+~:-]+", expected_version)), "expected version is invalid")
    require(
        bool(re.fullmatch(r"[0-9a-f]{64}", expected_package_sha256)),
        "expected package digest must be a SHA-256 value",
    )
    require(expected_source_date_epoch > 0, "expected source epoch is invalid")
    require(
        bool(re.fullmatch(r"[0-9a-f]{64}", expected_public_key_sha256)),
        "expected public-key digest must be a SHA-256 value",
    )
    require(
        bool(
            re.fullmatch(
                r"https://github\.com/Beowxlf/northgate-rmm/actions/runs/[1-9][0-9]*",
                expected_invocation_id,
            )
        ),
        "expected invocation identifier is invalid",
    )
    for path, label in (
        (spdx_schema, "SPDX schema"),
        (spdx_validator, "SPDX validator"),
    ):
        require(path.is_file() and not path.is_symlink(), f"{label} is missing or unsafe")

    manifest_path = root / "release-manifest.json"
    public_key = root / "release-test.pub"
    signature_bundle = root / "release-manifest.sigstore.json"
    for path in (manifest_path, public_key, signature_bundle):
        require(path.is_file() and not path.is_symlink(), f"missing or unsafe file: {path.name}")

    try:
        subprocess.run(
            [
                cosign,
                "verify-blob",
                "--key",
                str(public_key),
                "--bundle",
                str(signature_bundle),
                "--insecure-ignore-tlog",
                str(manifest_path),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    except OSError as error:
        raise VerificationError("Cosign could not be executed") from error
    except subprocess.CalledProcessError as error:
        detail = error.stderr.strip() or "Cosign returned no diagnostic"
        raise VerificationError(
            f"release manifest signature verification failed: {detail}"
        ) from error

    manifest = load_json(manifest_path)
    require(manifest.get("schemaVersion") == 1, "unsupported manifest schema")
    require(manifest.get("gate") == "G2B", "manifest is not a G2B candidate")
    require(manifest.get("product") == "northgate-rmm-agent", "unexpected product")
    require(manifest.get("version") == expected_version, "release version mismatch")
    require(manifest.get("architecture") == "amd64", "release architecture mismatch")
    require(manifest.get("releaseCandidate") is True, "release-candidate marker is absent")
    require(manifest.get("publicationAuthorized") is False, "publication must remain unauthorized")
    require(manifest.get("deploymentAuthorized") is False, "deployment must remain unauthorized")

    source = manifest.get("source")
    require(isinstance(source, dict), "source metadata is missing")
    require(source.get("repository") == "https://github.com/Beowxlf/northgate-rmm", "repository mismatch")
    require(source.get("commit") == expected_commit, "source commit mismatch")

    build = manifest.get("build")
    require(isinstance(build, dict), "build metadata is missing")
    require(
        build.get("sourceDateEpoch") == expected_source_date_epoch,
        "source epoch mismatch",
    )
    expected_build_type = "https://github.com/Beowxlf/northgate-rmm/.github/workflows/g2b-release-trust.yml"
    require(build.get("buildType") == expected_build_type, "build type mismatch")
    invocation_id = build.get("invocationId")
    require(invocation_id == expected_invocation_id, "invocation identifier mismatch")

    signing = manifest.get("signing")
    require(isinstance(signing, dict), "signing metadata is missing")
    require(signing.get("profile") == "test-only-ephemeral", "unexpected signing profile")
    key_path = evidence_path(root, signing.get("publicKey"), "public key")
    require(key_path == public_key, "manifest names an unexpected public key")
    require(
        digest(public_key) == expected_public_key_sha256,
        "public key does not match the independently supplied trust pin",
    )

    artifacts = manifest.get("artifacts")
    require(isinstance(artifacts, dict), "artifact evidence is missing")
    require(set(artifacts) == {"package", "sbom", "provenance"}, "artifact set is not exact")
    package = evidence_path(root, artifacts.get("package"), "package")
    sbom_path = evidence_path(root, artifacts.get("sbom"), "SBOM")
    provenance_path = evidence_path(root, artifacts.get("provenance"), "provenance")
    require(
        digest(package) == expected_package_sha256,
        "package does not match the independently supplied build digest",
    )

    expected_package_name = f"northgate-rmm-agent_{expected_version}_amd64.deb"
    require(package.name == expected_package_name, "package filename mismatch")
    require(sbom_path.name == f"{expected_package_name}.spdx.json", "SBOM filename mismatch")
    require(
        provenance_path.name == f"{expected_package_name}.provenance.json",
        "provenance filename mismatch",
    )
    require(artifacts["sbom"].get("format") == "SPDX-2.3", "SBOM format mismatch")
    require(
        artifacts["provenance"].get("predicateType") == "https://slsa.dev/provenance/v1",
        "provenance type mismatch",
    )

    expected_files = {
        manifest_path.name,
        public_key.name,
        signature_bundle.name,
        package.name,
        sbom_path.name,
        provenance_path.name,
    }
    actual_files: set[str] = set()
    for path in root.iterdir():
        require(path.is_file() and not path.is_symlink(), f"unexpected non-regular entry: {path.name}")
        actual_files.add(path.name)
    require(actual_files == expected_files, "candidate file set is not exact")
    require(not any(name.endswith((".key", ".p12", ".pfx")) for name in actual_files), "private key material is present")

    require(dpkg_field(package, "Package") == "northgate-rmm-agent", "Debian package name mismatch")
    require(dpkg_field(package, "Version") == expected_version, "Debian package version mismatch")
    require(dpkg_field(package, "Architecture") == "amd64", "Debian package architecture mismatch")

    sbom = load_json(sbom_path)
    try:
        subprocess.run(
            ["node", str(spdx_validator), str(spdx_schema), str(sbom_path)],
            check=True,
            capture_output=True,
            text=True,
        )
    except OSError as error:
        raise VerificationError("SPDX schema validator could not be executed") from error
    except subprocess.CalledProcessError as error:
        detail = error.stderr.strip() or "validator returned no diagnostic"
        raise VerificationError(f"SPDX 2.3 schema validation failed: {detail}") from error
    require(sbom.get("spdxVersion") == "SPDX-2.3", "SBOM is not SPDX 2.3")
    require(sbom.get("dataLicense") == "CC0-1.0", "SBOM data license mismatch")
    require(sbom.get("SPDXID") == "SPDXRef-DOCUMENT", "SBOM document identity mismatch")
    require(isinstance(sbom.get("name"), str) and sbom["name"], "SBOM document name is missing")
    require(
        isinstance(sbom.get("documentNamespace"), str)
        and sbom["documentNamespace"].startswith(("https://", "http://")),
        "SBOM document namespace is invalid",
    )
    creation = sbom.get("creationInfo")
    require(isinstance(creation, dict), "SBOM creation information is missing")
    require(isinstance(creation.get("created"), str) and creation["created"], "SBOM creation time is missing")
    creators = creation.get("creators")
    require(
        isinstance(creators, list)
        and any(isinstance(item, str) and item.startswith("Tool: syft-") for item in creators),
        "SBOM does not identify Syft as its creator",
    )
    packages = sbom.get("packages")
    require(isinstance(packages, list) and len(packages) > 0, "SBOM package inventory is empty")
    candidate_packages = [
        item
        for item in packages
        if isinstance(item, dict)
        and item.get("name") == "northgate-rmm-agent"
        and item.get("versionInfo") == expected_version
    ]
    require(
        len(candidate_packages) == 1,
        "SBOM does not identify exactly one Debian release candidate",
    )
    candidate_package = candidate_packages[0]
    checksums = candidate_package.get("checksums")
    require(isinstance(checksums, list), "SBOM package checksums are missing")
    require(
        any(
            isinstance(item, dict)
            and item.get("algorithm") == "SHA256"
            and item.get("checksumValue") == digest(package)
            for item in checksums
        ),
        "SBOM package checksum does not bind the candidate bytes",
    )
    candidate_spdx_id = candidate_package.get("SPDXID")
    require(isinstance(candidate_spdx_id, str), "SBOM package identity is missing")
    described = candidate_spdx_id in (sbom.get("documentDescribes") or [])
    if not described:
        relationships = sbom.get("relationships") or []
        described = any(
            isinstance(item, dict)
            and item.get("spdxElementId") == "SPDXRef-DOCUMENT"
            and item.get("relationshipType") == "DESCRIBES"
            and item.get("relatedSpdxElement") == candidate_spdx_id
            for item in relationships
        )
    require(described, "SBOM document does not describe the candidate package")

    provenance = load_json(provenance_path)
    require(provenance.get("_type") == "https://in-toto.io/Statement/v1", "provenance statement type mismatch")
    require(provenance.get("predicateType") == "https://slsa.dev/provenance/v1", "provenance predicate mismatch")
    subjects = provenance.get("subject")
    require(isinstance(subjects, list) and len(subjects) == 1, "provenance subject set is not exact")
    require(subjects[0].get("name") == package.name, "provenance subject name mismatch")
    require(subjects[0].get("digest") == {"sha256": digest(package)}, "provenance subject digest mismatch")
    predicate = provenance.get("predicate")
    require(isinstance(predicate, dict), "provenance predicate is missing")
    definition = predicate.get("buildDefinition")
    require(isinstance(definition, dict), "provenance build definition is missing")
    require(definition.get("buildType") == expected_build_type, "provenance build type mismatch")
    dependencies = definition.get("resolvedDependencies")
    require(isinstance(dependencies, list) and len(dependencies) == 1, "resolved source is not exact")
    require(
        dependencies[0].get("uri")
        == f"git+https://github.com/Beowxlf/northgate-rmm@{expected_commit}",
        "provenance source URI mismatch",
    )
    require(dependencies[0].get("digest") == {"gitCommit": expected_commit}, "provenance source digest mismatch")
    parameters = definition.get("externalParameters")
    require(
        parameters
        == {"architecture": "amd64", "releaseCandidate": True, "version": expected_version},
        "provenance external parameters mismatch",
    )
    internal = definition.get("internalParameters")
    require(isinstance(internal, dict), "provenance internal parameters are missing")
    require(internal.get("publicationAuthorized") is False, "provenance publication boundary is absent")
    require(internal.get("signingProfile") == "test-only-ephemeral", "provenance signing boundary is absent")
    require(internal.get("sourceDateEpoch") == expected_source_date_epoch, "source epoch disagreement")
    details = predicate.get("runDetails")
    require(isinstance(details, dict), "provenance run details are missing")
    require(details.get("builder") == {"id": expected_build_type}, "provenance builder mismatch")
    require(details.get("metadata") == {"invocationId": invocation_id}, "provenance invocation mismatch")

    return {
        "gate": "G2B",
        "source_commit": expected_commit,
        "source_date_epoch": expected_source_date_epoch,
        "version": expected_version,
        "package_sha256": digest(package),
        "package_bytes": package.stat().st_size,
        "sbom_sha256": digest(sbom_path),
        "sbom_packages": len(packages),
        "provenance_sha256": digest(provenance_path),
        "test_public_key_sha256": digest(public_key),
        "signature_verified": True,
        "publication_authorized": False,
        "deployment_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate")
    parser.add_argument("expected_commit")
    parser.add_argument("expected_version")
    parser.add_argument("expected_package_sha256")
    parser.add_argument("expected_source_date_epoch", type=int)
    parser.add_argument("expected_public_key_sha256")
    parser.add_argument("expected_invocation_id")
    parser.add_argument("--cosign", default="cosign")
    parser.add_argument("--spdx-schema", type=pathlib.Path, required=True)
    parser.add_argument("--spdx-validator", type=pathlib.Path, required=True)
    args = parser.parse_args()
    try:
        result = verify(
            pathlib.Path(args.candidate).resolve(),
            args.expected_commit,
            args.expected_version,
            args.expected_package_sha256,
            args.expected_source_date_epoch,
            args.expected_public_key_sha256,
            args.expected_invocation_id,
            args.cosign,
            args.spdx_schema.resolve(),
            args.spdx_validator.resolve(),
        )
    except VerificationError as error:
        print(f"verification failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
