import pytest

from northgate_rmm.remote_policy import parse_remote_targets, rdp_security
from tests.test_browser_rdp import configuration


@pytest.mark.parametrize(
    "pin", ["", "sha1:" + "11" * 20, "sha256:bad", "sha256:" + "gg" * 32]
)
def test_xrdp_requires_valid_sha256_pin(pin):
    entries = configuration()
    entries[1]["parameters"].update(security="tls", **{"cert-fingerprints": pin})
    with pytest.raises(ValueError):
        parse_remote_targets(entries)


@pytest.mark.parametrize("pin", ["11" * 32, ":".join(["ab"] * 32)])
def test_xrdp_accepts_explicit_pinned_tls(pin):
    assert (
        rdp_security({"security": "tls", "cert-fingerprints": "sha256:" + pin}) == "tls"
    )


@pytest.mark.parametrize("security", ["rdp", "any", "negotiate", "", "TLS"])
def test_no_legacy_rdp_fallback(security):
    with pytest.raises(ValueError):
        rdp_security({"security": security, "cert-fingerprints": "sha256:" + "11" * 32})


def test_windows_retains_nla_default():
    assert rdp_security({}) == "nla"


@pytest.mark.parametrize("security", ["nla", "tls"])
def test_workspace_offers_browser_and_native_desktop_on_both_platforms(security):
    import asyncio

    from aiohttp.test_utils import TestClient, TestServer

    from northgate_rmm.remote_gateway import RemoteGateway
    from northgate_rmm.remote_workspace import RemoteWorkspace

    async def scenario():
        entries = configuration()
        entries[1]["parameters"]["security"] = security
        targets = parse_remote_targets(entries)
        gateway = RemoteGateway(None, targets, bytes(16), "https://operator.test")

        async def principal(*args, **kwargs):
            return None

        gateway.principal = principal
        app = gateway.application()
        RemoteWorkspace(gateway).register(app)
        async with TestClient(TestServer(app)) as client:
            response = await client.get(f"/remote/{next(iter(targets))}/workspace")
            assert response.status == 200
            html = await response.text()
            assert "Open browser desktop" in html
            assert "Download native RDP connection" in html

    asyncio.run(scenario())


@pytest.mark.parametrize("security", ["nla", "tls"])
def test_native_rdp_file_keeps_tls_validation_and_windowed_session(security):
    import asyncio

    from aiohttp.test_utils import TestClient, TestServer

    from northgate_rmm.remote_gateway import RemoteGateway

    async def scenario():
        entries = configuration()
        entries[1]["parameters"]["security"] = security
        targets = parse_remote_targets(entries)
        gateway = RemoteGateway(None, targets, bytes(16), "https://operator.test")

        async def noop(*args, **kwargs):
            return None

        gateway.principal = noop
        gateway.audit = noop
        async with TestClient(TestServer(gateway.application())) as client:
            response = await client.get(f"/remote/{next(iter(targets))}/desktop.rdp")
            assert response.status == 200
            content = (await response.read()).decode("utf-16")
            assert "full address:s:10.20.30.40:3389" in content
            assert "username:s:remote" in content
            assert "authentication level:i:2" in content
            assert f"enablecredsspsupport:i:{int(security == 'nla')}" in content
            assert "screen mode id:i:1" in content
            assert "dynamic resolution:i:1" in content
            assert "synthetic" not in content
            assert "password" not in content
            assert "attachment;" in response.headers["Content-Disposition"]

    asyncio.run(scenario())
