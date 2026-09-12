"""Optional real PostgreSQL adapter qualification in a private test schema."""

import os
from typing import Any
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import make_conninfo

from northgate_rmm.operations_store import Conflict, OperationsStore

TEST_DSN = os.environ.get("RMM_OPERATIONS_TEST_DSN")
pytestmark = [
    pytest.mark.postgresql,
    pytest.mark.skipif(
        not TEST_DSN, reason="An isolated RMM_OPERATIONS_TEST_DSN is required"
    ),
]


def test_postgres_migration_transactions_versions_and_request_replay(
    tmp_path: Any,
) -> None:
    assert TEST_DSN is not None
    schema = "rmm_ops_test_" + uuid4().hex
    with psycopg.connect(TEST_DSN, autocommit=True) as connection:
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    try:
        dsn = make_conninfo(TEST_DSN, options="-c search_path=" + schema)
        store = OperationsStore.postgres(dsn, tmp_path / "artifacts", b"k" * 16)
        store.migrate()
        store.verify()
        key, request = str(uuid4()), str(uuid4())
        value = {"name": "Synthetic case", "endpoints": []}
        first = store.transaction(
            "test",
            request,
            value,
            lambda db: store.put(db, "case", key, value, "test", 0),
        )
        assert (
            store.transaction(
                "test",
                request,
                value,
                lambda db: pytest.fail("Replay must not execute"),
            )
            == first
        )
        with pytest.raises(Conflict):
            store.transaction(
                "test",
                str(uuid4()),
                value,
                lambda db: store.put(db, "case", key, value, "test", 0),
            )
        assert len(store.versions("case", key)) == 1
        assert len(store.history("case", key)) == 1
    finally:
        with psycopg.connect(TEST_DSN, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema))
            )
