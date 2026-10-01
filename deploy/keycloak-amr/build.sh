#!/bin/sh
set -eu
test "$#" -eq 2 || { echo 'Usage: build.sh KEYCLOAK_HOME NEW_OUTPUT_DIRECTORY' >&2; exit 2; }
keycloak=$1
output=$2
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
test -f "$keycloak/lib/lib/main/org.keycloak.keycloak-services-26.7.3.jar"
test ! -e "$output"
mkdir -p "$output/classes" "$output/tests"
javac --release 17 -cp "$keycloak/lib/lib/main/*" -d "$output/classes" \
    "$source_dir/src/com/northgate/rmm/IntrospectableAmrMapper.java"
cp -R "$source_dir/resources/META-INF" "$output/classes/"
jar --create --file "$output/northgate-amr-introspection.jar" -C "$output/classes" .
javac --release 17 -cp "$keycloak/lib/lib/main/*:$output/classes" -d "$output/tests" \
    "$source_dir/test/AmrMapperTest.java"
java -cp "$keycloak/lib/lib/boot/*:$keycloak/lib/lib/main/*:$output/classes:$output/tests" AmrMapperTest
sha256sum "$output/northgate-amr-introspection.jar"
