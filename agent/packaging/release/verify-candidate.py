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


def verify(root: pathlib.Path, expected_commit: str, expected_version: str, cosign: str) -> dict[str, Any]:
    require(root.is_dir(), "candidate directory is missing")
    require(bool(re.fullmatch(r"[0-9a-f]{40}", expected_commit)), "expected commit must be a full SHA")
    require(bool(re.fullmatch(r"[0-9A-Za-z.+~:-]+", expected_version)), "expected version is invalid")

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
    require(isinstance(build.get("sourceDateEpoch"), int) and build["sourceDateEpoch"] > 0, "source epoch is invalid")
    expected_build_type = "https://github.com/Beowxlf/northgate-rmm/.github/workflows/g2b-release-trust.yml"
    require(build.get("buildType") == expected_build_type, "build type mismatch")
    invocation_id = build.get("invocationId")
    require(
        isinstance(invocation_id, str)
        and invocation_id.startswith("https://github.com/Beowxlf/northgate-rmm/actions/runs/"),
        "invocation identifier mismatch",
    )

    signing = manifest.get("signing")
    require(isinstance(signing, dict), "signing metadata is missing")
    require(signing.get("profile") == "test-only-ephemeral", "unexpected signing profile")
    key_path = evidence_path(root, signing.get("publicKey"), "public key")
    require(key_path == public_key, "manifest names an unexpected public key")

    artifacts = manifest.get("artifacts")
    require(isinstance(artifacts, dict), "artifact evidence is missing")
    require(set(artifacts) == {"package", "sbom", "provenance"}, "artifact set is not exact")
    package = evidence_path(root, artifacts.get("package"), "package")
    sbom_path = evidence_path(root, artifacts.get("sbom"), "SBOM")
    provenance_path = evidence_path(root, artifacts.get("provenance"), "provenance")

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
    require(sbom.get("spdxVersion") == "SPDX-2.3", "SBOM is not SPDX 2.3")
    require(sbom.get("dataLicense") == "CC0-1.0", "SBOM data license mismatch")
    packages = sbom.get("packages")
    require(isinstance(packages, list) and len(packages) > 0, "SBOM package inventory is empty")
    require(
        any(
            isinstance(item, dict)
            and item.get("name") == "northgate-rmm-agent"
            and item.get("versionInfo") == expected_version
            for item in packages
        ),
        "SBOM does not identify the Debian release candidate",
    )

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
    require(internal.get("sourceDateEpoch") == build.get("sourceDateEpoch"), "source epoch disagreement")
    details = predicate.get("runDetails")
    require(isinstance(details, dict), "provenance run details are missing")
    require(details.get("builder") == {"id": expected_build_type}, "provenance builder mismatch")
    require(details.get("metadata") == {"invocationId": invocation_id}, "provenance invocation mismatch")

    return {
        "gate": "G2B",
        "source_commit": expected_commit,
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
    parser.add_argument("--cosign", default="cosign")
    args = parser.parse_args()
    try:
        result = verify(
            pathlib.Path(args.candidate).resolve(),
            args.expected_commit,
            args.expected_version,
            args.cosign,
        )
    except VerificationError as error:
        print(f"verification failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
