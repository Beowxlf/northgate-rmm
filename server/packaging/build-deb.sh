#!/bin/sh
set -eu

if [ "$#" -ne 4 ]; then
  echo "usage: build-deb.sh VERSION APPLICATION_WHEEL WHEELHOUSE OUTPUT_DIRECTORY" >&2
  exit 64
fi

version="$1"
application_wheel="$2"
wheelhouse="$3"
output_directory="$4"
case "$version" in
  *[!0-9A-Za-z.+~:-]*|'')
    echo "invalid Debian version" >&2
    exit 65
    ;;
esac
case "${SOURCE_DATE_EPOCH:-}" in
  ''|*[!0-9]*)
    echo "SOURCE_DATE_EPOCH must be a non-negative integer" >&2
    exit 66
    ;;
esac
if [ ! -f "$application_wheel" ] || [ -L "$application_wheel" ]; then
  echo "application wheel must be a regular non-symlink file" >&2
  exit 67
fi
if [ ! -d "$wheelhouse" ] || [ -L "$wheelhouse" ]; then
  echo "runtime wheelhouse must be a non-symlink directory" >&2
  exit 68
fi

script_directory="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
expected_wheels="$(wc -l < "$script_directory/runtime-wheels.sha256" | tr -d ' ')"
actual_wheels="$(find "$wheelhouse" -maxdepth 1 -type f -name '*.whl' | wc -l | tr -d ' ')"
if [ "$actual_wheels" != "$expected_wheels" ]; then
  echo "runtime wheelhouse file count does not match the pinned manifest" >&2
  exit 69
fi
if find "$wheelhouse" -maxdepth 1 -type l | grep . >/dev/null; then
  echo "runtime wheelhouse contains a symlink" >&2
  exit 70
fi
(cd "$wheelhouse" && sha256sum --check --strict "$script_directory/runtime-wheels.sha256")

stage="$(mktemp -d)"
cleanup() {
  rm -rf -- "$stage"
}
trap cleanup EXIT HUP INT TERM

site_packages="$stage/usr/lib/northgate-rmm-server/site-packages"
install -d -m 0755 "$stage/DEBIAN" "$site_packages"
install -d -m 0755 "$stage/usr/libexec/northgate-rmm-server"
install -d -m 0755 "$stage/usr/lib/systemd/system"
install -d -m 0755 "$stage/etc/northgate-rmm"

LC_ALL=C
export LC_ALL
for wheel in "$application_wheel" "$wheelhouse"/*.whl; do
  python3 -m zipfile -e "$wheel" "$site_packages"
done
find "$site_packages" -type d -exec chmod 0755 {} +
find "$site_packages" -type f -exec chmod 0644 {} +
find "$site_packages" -type d -name __pycache__ -prune -exec rm -rf -- {} +
find "$site_packages" -type f -name '*.pyc' -delete

for service in agent enrollment operator; do
  unit_service="$service"
  if [ "$service" = "agent" ]; then
    unit_service=agent-ingress
  fi
  install -m 0755 "$script_directory/launcher.py" \
    "$stage/usr/libexec/northgate-rmm-server/northgate-rmm-${service}-service"
  sed 's#/opt/northgate-rmm/venv/bin#/usr/libexec/northgate-rmm-server#' \
    "$script_directory/../../deploy/systemd/northgate-rmm-${unit_service}.service" > \
    "$stage/usr/lib/systemd/system/northgate-rmm-${unit_service}.service"
  chmod 0644 \
    "$stage/usr/lib/systemd/system/northgate-rmm-${unit_service}.service"
  install -m 0644 "$script_directory/../../deploy/${service}-service.example.json" \
    "$stage/etc/northgate-rmm/${service}-service.json.example"
done

sed "s/@VERSION@/$version/g" "$script_directory/debian/control.in" > \
  "$stage/DEBIAN/control"
install -m 0644 "$script_directory/debian/conffiles" "$stage/DEBIAN/conffiles"
for maintainer_script in preinst postinst prerm postrm; do
  install -m 0755 "$script_directory/debian/$maintainer_script" \
    "$stage/DEBIAN/$maintainer_script"
done

find "$stage" -print0 | xargs -0 touch --date="@$SOURCE_DATE_EPOCH"
mkdir -p -- "$output_directory"
package="$output_directory/northgate-rmm-server_${version}_amd64.deb"
dpkg-deb --root-owner-group --build "$stage" "$package" >/dev/null
printf '%s\n' "$package"
