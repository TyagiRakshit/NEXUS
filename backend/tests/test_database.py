from collections.abc import Callable
from typing import Any

import pytest


def load_check_database() -> Callable[[str], str]:
    try:
        from app.database import check_database
    except (ImportError, ModuleNotFoundError):
        pytest.fail("check_database is not implemented")
    return check_database


class FakeResult:
    def fetchone(self) -> tuple[int]:
        return (1,)


class FakeConnection:
    def __init__(self) -> None:
        self.queries: list[str] = []

    def __enter__(self) -> "FakeConnection":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, query: str) -> FakeResult:
        self.queries.append(query)
        return FakeResult()


def test_database_check_executes_select_one(monkeypatch: pytest.MonkeyPatch) -> None:
    check_database = load_check_database()
    connection = FakeConnection()
    observed: dict[str, Any] = {}

    def fake_connect(
        database_url: str, *, connect_timeout: int, options: str | None = None
    ) -> FakeConnection:
        observed.update(
            database_url=database_url,
            connect_timeout=connect_timeout,
            options=options,
        )
        return connection

    monkeypatch.setattr("app.database.psycopg.connect", fake_connect)

    assert check_database("postgresql://example") == "healthy"
    assert observed == {
        "database_url": "postgresql://example",
        "connect_timeout": 2,
        "options": "-c statement_timeout=2000",
    }
    assert connection.queries == ["SELECT 1"]


def test_database_check_reports_connection_failure_as_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    check_database = load_check_database()

    def failed_connect(
        _database_url: str, *, connect_timeout: int, options: str
    ) -> None:
        raise RuntimeError(
            f"secret connection detail after {connect_timeout} seconds with {options}"
        )

    monkeypatch.setattr("app.database.psycopg.connect", failed_connect)

    assert check_database("postgresql://example") == "unavailable"


def test_database_check_returns_only_the_public_failure_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    check_database = load_check_database()

    def timed_out(_database_url: str, *, connect_timeout: int, options: str) -> None:
        raise TimeoutError(
            f"private timeout detail after {connect_timeout} seconds with {options}"
        )

    monkeypatch.setattr("app.database.psycopg.connect", timed_out)

    result = check_database("postgresql://example")

    assert result == "unavailable"
    assert "private" not in result
