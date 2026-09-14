import asyncio
from types import SimpleNamespace
from uuid import uuid4

import pytest

from northgate_rmm.secrets_api import validate_fields
from tests.test_secrets_api import fixture


def test_account_password_is_stored_and_revealed_without_remote_binding(tmp_path):
    async def scenario():
        endpoint, identity, config, _, gateway, provider, api = fixture(tmp_path)
        identifier = str(uuid4())
        fields = {"username": "lab-fixture", "password": "synthetic-only"}
        request = SimpleNamespace()
        await api.perform(
            request,
            endpoint,
            identity,
            gateway.user,
            config,
            "create",
            {
                "request_id": identifier,
                "label": "Lab account",
                "kind": "account",
                "fields": fields,
            },
        )
        record = api.state.get("records", identifier)
        assert record["kind"] == "account" and not record["use_for_remote"]
        assert "password" not in record
        assert provider.read(record["path"]) == fields
        with pytest.raises(ValueError):
            await api.perform(
                request,
                endpoint,
                identity,
                gateway.user,
                config,
                "edit",
                {
                    "secret_id": identifier,
                    "label": "Lab account",
                    "use_for_remote": True,
                },
            )
        assert not api.state.get("records", identifier)["use_for_remote"]

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "fields",
    [
        {"username": "lab"},
        {"password": "synthetic"},
        {"username": "lab", "password": "synthetic", "host": "other"},
    ],
)
def test_account_password_schema_rejects_missing_and_unexpected_fields(fields):
    with pytest.raises(ValueError):
        validate_fields("account", fields)
