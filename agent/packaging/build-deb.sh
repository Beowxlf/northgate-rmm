#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: build-deb.sh VERSION BINARY OUTPUT_DIRECTORY" >&2
  exit 64
fi

version="$1"
binary="$2"
output_directory="$3"
case "$version" in
  *[!0-9A-Za-z.+~:-]*|'')
    echo "invalid Debian version" >&2
    exit 65
    ;;
esac
if [ ! -f "$binary" ] || [ ! -x "$binary" ]; then
  echo "binary must be an executable regular file" >&2
  exit 66
fi
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  echo "SOURCE_DATE_EPOCH is required" >&2
  exit 67
fi

script_directory="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
stage="$(mktemp -d)"
cleanup() {
  rm -rf -- "$stage"
}
trap cleanup EXIT HUP INT TERM

install -d -m 0755 "$stage/DEBIAN"
install -d -m 0755 "$stage/usr/libexec/northgate-rmm"
install -d -m 0755 "$stage/usr/lib/systemd/system"
install -d -m 0755 "$stage/etc/northgate-rmm"
install -m 0755 "$binary" "$stage/usr/libexec/northgate-rmm/northgate-rmm-agent"
install -m 0644 "$script_directory/debian/northgate-rmm-agent.service" \
  "$stage/usr/lib/systemd/system/northgate-rmm-agent.service"
install -m 0644 "$script_directory/debian/agent.json.example" \
  "$stage/etc/northgate-rmm/agent.json.example"
sed "s/@VERSION@/$version/g" "$script_directory/debian/control.in" > "$stage/DEBIAN/control"
install -m 0644 "$script_directory/debian/conffiles" "$stage/DEBIAN/conffiles"
for maintainer_script in postinst prerm postrm; do
  install -m 0755 "$script_directory/debian/$maintainer_script" "$stage/DEBIAN/$maintainer_script"
done

find "$stage" -print0 | xargs -0 touch --date="@$SOURCE_DATE_EPOCH"
mkdir -p -- "$output_directory"
package="$output_directory/northgate-rmm-agent_${version}_amd64.deb"
dpkg-deb --root-owner-group --build "$stage" "$package" >/dev/null
printf '%s\n' "$package"
