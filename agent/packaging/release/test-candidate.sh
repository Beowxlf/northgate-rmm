#!/bin/sh
set -eu

if [ "$#" -ne 5 ]; then
  echo "usage: test-candidate.sh CANDIDATE EXPECTED_COMMIT EXPECTED_VERSION EXPECTED_KEY_SHA256 RESULT" >&2
  exit 64
fi

candidate=$1
commit=$2
version=$3
expected_key_sha256=$4
result=$5
script_directory="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
verifier="$script_directory/verify-candidate.py"
temporary=$(mktemp -d)
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT HUP INT TERM

python3 "$verifier" \
  "$candidate" "$commit" "$version" "$expected_key_sha256" > "$result"

expect_failure() {
  name=$1
  directory=$2
  expected_commit=${3:-$commit}
  expected_key=${4:-$expected_key_sha256}
  if python3 "$verifier" \
    "$directory" "$expected_commit" "$version" "$expected_key" \
    >"$temporary/$name.stdout" 2>"$temporary/$name.stderr"; then
    echo "negative verification unexpectedly passed: $name" >&2
    exit 70
  fi
}

copy_candidate() {
  name=$1
  directory="$temporary/$name"
  mkdir "$directory"
  cp -a "$candidate/." "$directory/"
  printf '%s\n' "$directory"
}

tampered_package=$(copy_candidate tampered-package)
printf 'tamper' >> "$tampered_package/northgate-rmm-agent_${version}_amd64.deb"
expect_failure tampered-package "$tampered_package"

tampered_manifest=$(copy_candidate tampered-manifest)
printf ' ' >> "$tampered_manifest/release-manifest.json"
expect_failure tampered-manifest "$tampered_manifest"

tampered_sbom=$(copy_candidate tampered-sbom)
printf ' ' >> "$tampered_sbom/northgate-rmm-agent_${version}_amd64.deb.spdx.json"
expect_failure tampered-sbom "$tampered_sbom"

tampered_provenance=$(copy_candidate tampered-provenance)
printf ' ' >> "$tampered_provenance/northgate-rmm-agent_${version}_amd64.deb.provenance.json"
expect_failure tampered-provenance "$tampered_provenance"

private_key=$(copy_candidate private-key)
: > "$private_key/cosign.key"
expect_failure private-key "$private_key"

wrong_commit=$(printf '0%.0s' $(seq 1 40))
if [ "$wrong_commit" = "$commit" ]; then
  wrong_commit=$(printf '1%.0s' $(seq 1 40))
fi
expect_failure wrong-commit "$candidate" "$wrong_commit"

wrong_key=$(printf '0%.0s' $(seq 1 64))
if [ "$wrong_key" = "$expected_key_sha256" ]; then
  wrong_key=$(printf '1%.0s' $(seq 1 64))
fi
expect_failure wrong-key "$candidate" "$commit" "$wrong_key"

python3 - "$result" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
result = json.loads(path.read_text(encoding="utf-8"))
result["negative_tests"] = [
    "package_digest_tamper",
    "manifest_signature_tamper",
    "sbom_digest_tamper",
    "provenance_digest_tamper",
    "private_key_escape",
    "wrong_source_commit",
    "wrong_public_key_pin",
]
path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

cat "$result"
