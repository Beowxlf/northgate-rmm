#!/bin/sh
set -eu

if [ "$#" -ne 7 ]; then
  echo "usage: create-candidate.sh PACKAGE OUTPUT VERSION COMMIT EPOCH BUILD_TYPE INVOCATION_ID" >&2
  exit 64
fi

package=$1
output=$2
version=$3
commit=$4
epoch=$5
build_type=$6
invocation_id=$7

case "$version" in
  *[!0-9A-Za-z.+~:-]*|'') echo "invalid Debian version" >&2; exit 65 ;;
esac
case "$commit" in
  *[!0-9a-f]*|'') echo "invalid source commit" >&2; exit 66 ;;
esac
if [ "${#commit}" -ne 40 ]; then
  echo "source commit must be a full SHA" >&2
  exit 66
fi
case "$epoch" in
  *[!0-9]*|'') echo "invalid source epoch" >&2; exit 67 ;;
esac
if [ ! -f "$package" ] || [ -L "$package" ]; then
  echo "package must be a regular non-symlink file" >&2
  exit 68
fi
for tool in cosign dpkg-deb python3 sha256sum syft; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "required tool is unavailable: $tool" >&2
    exit 69
  }
done
if [ -e "$output" ] && [ -n "$(find "$output" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
  echo "output directory must be empty" >&2
  exit 70
fi

expected_name="northgate-rmm-agent_${version}_amd64.deb"
if [ "$(basename "$package")" != "$expected_name" ]; then
  echo "package filename does not match version and architecture" >&2
  exit 71
fi
if [ "$(dpkg-deb --field "$package" Package)" != "northgate-rmm-agent" ] ||
  [ "$(dpkg-deb --field "$package" Version)" != "$version" ] ||
  [ "$(dpkg-deb --field "$package" Architecture)" != "amd64" ]; then
  echo "package control metadata does not match the release candidate" >&2
  exit 72
fi

mkdir -p "$output"
candidate_package="$output/$expected_name"
sbom="$output/$expected_name.spdx.json"
provenance="$output/$expected_name.provenance.json"
manifest="$output/release-manifest.json"
public_key="$output/release-test.pub"
signature_bundle="$output/release-manifest.sigstore.json"
install -m 0644 "$package" "$candidate_package"

SYFT_CHECK_FOR_APP_UPDATE=false syft scan "file:$candidate_package" \
  --output "spdx-json=$sbom" >/dev/null

python3 - "$provenance" "$expected_name" "$commit" "$version" "$epoch" \
  "$build_type" "$invocation_id" <<'PY'
import hashlib
import json
import pathlib
import sys

destination, package_name, commit, version, epoch, build_type, invocation_id = sys.argv[1:]
package = pathlib.Path(destination).parent / package_name
statement = {
    "_type": "https://in-toto.io/Statement/v1",
    "predicateType": "https://slsa.dev/provenance/v1",
    "subject": [
        {
            "name": package_name,
            "digest": {"sha256": hashlib.sha256(package.read_bytes()).hexdigest()},
        }
    ],
    "predicate": {
        "buildDefinition": {
            "buildType": build_type,
            "externalParameters": {
                "architecture": "amd64",
                "releaseCandidate": True,
                "version": version,
            },
            "internalParameters": {
                "publicationAuthorized": False,
                "signingProfile": "test-only-ephemeral",
                "sourceDateEpoch": int(epoch),
            },
            "resolvedDependencies": [
                {
                    "uri": f"git+https://github.com/Beowxlf/northgate-rmm@{commit}",
                    "digest": {"gitCommit": commit},
                }
            ],
        },
        "runDetails": {
            "builder": {"id": build_type},
            "metadata": {"invocationId": invocation_id},
        },
    },
}
pathlib.Path(destination).write_text(
    json.dumps(statement, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

signing_directory=$(mktemp -d)
cleanup() {
  rm -rf -- "$signing_directory"
}
trap cleanup EXIT HUP INT TERM
COSIGN_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
export COSIGN_PASSWORD
(
  cd "$signing_directory"
  cosign generate-key-pair >/dev/null
)
install -m 0644 "$signing_directory/cosign.pub" "$public_key"

python3 - "$manifest" "$expected_name" "$commit" "$version" "$epoch" \
  "$build_type" "$invocation_id" <<'PY'
import hashlib
import json
import pathlib
import sys

destination, package_name, commit, version, epoch, build_type, invocation_id = sys.argv[1:]
root = pathlib.Path(destination).parent


def evidence(path):
    data = path.read_bytes()
    return {"path": path.name, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


package = root / package_name
sbom = root / f"{package_name}.spdx.json"
provenance = root / f"{package_name}.provenance.json"
public_key = root / "release-test.pub"
manifest = {
    "schemaVersion": 1,
    "gate": "G2B",
    "product": "northgate-rmm-agent",
    "version": version,
    "architecture": "amd64",
    "releaseCandidate": True,
    "publicationAuthorized": False,
    "deploymentAuthorized": False,
    "source": {
        "repository": "https://github.com/Beowxlf/northgate-rmm",
        "commit": commit,
    },
    "build": {
        "sourceDateEpoch": int(epoch),
        "buildType": build_type,
        "invocationId": invocation_id,
    },
    "signing": {
        "profile": "test-only-ephemeral",
        "publicKey": evidence(public_key),
    },
    "artifacts": {
        "package": evidence(package),
        "sbom": {**evidence(sbom), "format": "SPDX-2.3"},
        "provenance": {
            **evidence(provenance),
            "predicateType": "https://slsa.dev/provenance/v1",
        },
    },
}
pathlib.Path(destination).write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

cosign sign-blob --yes --tlog-upload=false \
  --key "$signing_directory/cosign.key" \
  --bundle "$signature_bundle" \
  "$manifest" >/dev/null

cleanup
trap - EXIT HUP INT TERM
if find "$output" -type f \( -name '*.key' -o -name 'cosign.key' \) | grep -q .; then
  echo "private signing material escaped into the candidate bundle" >&2
  exit 73
fi
