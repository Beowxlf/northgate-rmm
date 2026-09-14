"""Small OpenBao KV v2 client. The provider owns encryption and secret versions."""

from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote, urlsplit

from northgate_rmm.errors import ValidationError
from northgate_rmm.secure_files import regular_file_reference

MAX_VALUE = 65536
MAX_RESPONSE = 1024 * 1024


class VaultError(RuntimeError):
    """Public errors deliberately exclude provider bodies, URLs and credentials."""

    def __init__(self, status=503):
        self.status = status
        super().__init__("Secret provider request failed")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise VaultError(502)


def relative_path(value):
    if (
        not isinstance(value, str)
        or len(value) > 512
        or not re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*", value)
    ):
        raise ValueError("Invalid provider path")
    return value


class OpenBaoKV:
    def __init__(self, config):
        origin = config["origin"]
        url = urlsplit(origin)
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or url.path
            or url.query
            or url.fragment
        ):
            raise ValueError("OpenBao requires an exact HTTPS origin")
        self.origin = origin
        self.mount = relative_path(config["mount"])
        self.token_file = Path(config["token_file"])
        try:
            with regular_file_reference(
                Path(config["ca_file"]),
                label="OpenBao CA",
                maximum_bytes=262144,
                private=False,
            ) as ref:
                self.context = ssl.create_default_context(cafile=str(ref))
        except (ValidationError, OSError, ValueError):
            raise VaultError() from None
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            NoRedirect(),
            urllib.request.HTTPSHandler(context=self.context),
        )

    def _request(self, method, path, data=None, *, health=False):
        body = None if data is None else json.dumps(data, allow_nan=False).encode()
        if body and len(body) > MAX_VALUE:
            raise ValueError("Secret exceeds provider value limit")
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if not health:
            try:
                with regular_file_reference(
                    self.token_file,
                    label="OpenBao credential",
                    maximum_bytes=4096,
                    private=True,
                ) as ref:
                    token = ref.read_text(encoding="utf-8").strip()
            except (ValidationError, OSError, ValueError):
                raise VaultError() from None
            if not token or not token.isascii() or any(c.isspace() for c in token):
                raise VaultError()
            headers["X-Vault-Token"] = token
        request = urllib.request.Request(  # noqa: S310 - fixed validated HTTPS origin
            self.origin + "/v1/" + path, data=body, headers=headers, method=method
        )
        try:
            with self.opener.open(request, timeout=15) as response:
                raw = response.read(MAX_RESPONSE + 1)
                if len(raw) > MAX_RESPONSE:
                    raise VaultError(502)
                result = json.loads(raw) if raw else {}
                if not isinstance(result, dict):
                    raise VaultError(502)
                return result
        except urllib.error.HTTPError as error:
            if health and error.code in {429, 472, 473, 501, 503}:
                # Only expose fixed boolean fields from the health response.
                try:
                    raw = error.read(16385)
                    result = json.loads(raw)
                    if len(raw) > 16384 or not isinstance(result, dict):
                        raise VaultError(502)
                    return result
                except (ValueError, OSError):
                    raise VaultError(502) from None
            raise VaultError(error.code) from None
        except (OSError, ValueError, urllib.error.URLError):
            raise VaultError() from None

    def health(self):
        result = self._request(
            "GET", "sys/health?standbyok=true&perfstandbyok=true", health=True
        )
        return {
            "initialized": result.get("initialized") is True,
            "sealed": result.get("sealed") is not False,
            "standby": result.get("standby") is True,
        }

    def _path(self, section, path):
        return self.mount + "/" + section + "/" + quote(relative_path(path), safe="/")

    def metadata(self, path):
        result = self._request("GET", self._path("metadata", path)).get("data")
        if (
            not isinstance(result, dict)
            or type(result.get("current_version")) is not int
            or result["current_version"] < 0
            or not isinstance(result.get("versions", {}), dict)
            or any(not isinstance(v, dict) for v in result.get("versions", {}).values())
        ):
            raise VaultError(502)
        return result

    def read(self, path, version=None):
        suffix = ""
        if version is not None:
            if type(version) is not int or version < 1:
                raise ValueError("Invalid secret version")
            suffix = "?version=" + str(version)
        result = self._request("GET", self._path("data", path) + suffix).get("data")
        if (
            not isinstance(result, dict)
            or not isinstance(result.get("metadata"), dict)
            or not isinstance(result.get("data"), dict)
        ):
            raise VaultError(502)
        if result.get("metadata", {}).get("destroyed") or result.get(
            "metadata", {}
        ).get("deletion_time"):
            raise VaultError(404)
        fields = result["data"].get("fields")
        if not isinstance(fields, dict):
            raise VaultError(502)
        return fields

    def write(self, path, fields, *, cas):
        if type(cas) is not int or cas < 0 or not isinstance(fields, dict):
            raise ValueError("Invalid secret write")
        result = self._request(
            "POST",
            self._path("data", path),
            {"options": {"cas": cas}, "data": {"fields": fields}},
        )
        if (
            not isinstance(result.get("data"), dict)
            or type(result["data"].get("version")) is not int
            or result["data"]["version"] < 1
        ):
            raise VaultError(502)
        return result["data"]["version"]

    def configure_metadata(self, path, label, kind):
        self._request(
            "POST",
            self._path("metadata", path),
            {
                "cas_required": True,
                "max_versions": 20,
                "custom_metadata": {"label": label, "kind": kind},
            },
        )

    def versions(self, path, action, versions):
        if (
            action not in {"delete", "undelete"}
            or not versions
            or len(versions) > 20
            or any(type(x) is not int or x < 1 for x in versions)
        ):
            raise ValueError("Invalid version lifecycle request")
        self._request("POST", self._path(action, path), {"versions": versions})
