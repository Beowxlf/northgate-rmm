from pathlib import Path

from northgate_rmm.codec import decode_message
from northgate_rmm.domain import InventoryMessage, Platform


def test_go_agent_inventory_fixture_matches_control_plane_contract() -> None:
    fixture = Path(__file__).parent / "fixtures" / "agent_inventory_v1.json"

    message = decode_message(fixture.read_bytes())

    assert isinstance(message, InventoryMessage)
    assert message.payload.platform is Platform.LINUX
    assert message.payload.architecture == "amd64"
    assert message.payload.fields == (("os.id", "debian"),)
    assert message.payload.collector_complete is True
