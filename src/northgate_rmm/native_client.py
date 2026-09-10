"""Reusable native client and command-line entry point; secrets stay in local files."""

from __future__ import annotations

import argparse
import json
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from northgate_rmm.secure_files import regular_file_reference


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError(
            "RMM redirected the native request; credentials were not forwarded"
        )


class NativeClient:
    def __init__(self, configuration: Path):
        with regular_file_reference(
            configuration,
            label="native configuration",
            maximum_bytes=8192,
            private=True,
        ) as ref:
            config = json.loads(ref.read_text())
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
            raise ValueError("An exact HTTPS RMM origin is required")
        self.url = origin + "/native/v1/rpc"
        self.token_file = Path(config["token_file"])
        self.context = ssl.create_default_context(cafile=config["ca_file"])
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2

    def call(self, operation: str, **arguments):
        with regular_file_reference(
            self.token_file, label="native credential", maximum_bytes=256, private=True
        ) as ref:
            token = ref.read_text().strip()
        data = json.dumps(
            {"operation": operation, "arguments": arguments}, allow_nan=False
        ).encode()
        if len(data) > 1024 * 1024:
            raise ValueError("Native request exceeds 1 MiB")
        request = urllib.request.Request(  # noqa: S310 - exact HTTPS origin validated
            self.url,
            data=data,
            method="POST",
            headers={
                "Authorization": "Bearer " + token,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            NoRedirect(),
            urllib.request.HTTPSHandler(context=self.context),
        )
        try:
            with opener.open(request, timeout=200) as response:
                body = response.read(8 * 1024 * 1024 + 1)
                if len(body) > 8 * 1024 * 1024:
                    raise ValueError("Native response exceeds 8 MiB")
                if response.headers.get_content_type() != "application/json":
                    raise ValueError("Unexpected native response type")
                return json.loads(body)
        except urllib.error.HTTPError as error:
            raise RuntimeError(
                "RMM rejected the request (HTTP "
                + str(error.code)
                + "): "
                + error.read(1024).decode(errors="replace")
            ) from None


def main():
    parser = argparse.ArgumentParser(description="Native NorthGate RMM client")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("operation")
    parser.add_argument("--arguments", default="{}")
    args = parser.parse_args()
    print(
        json.dumps(
            NativeClient(args.config).call(
                args.operation, **json.loads(args.arguments)
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
