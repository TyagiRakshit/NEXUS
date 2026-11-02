from typing import Literal

import psycopg


DatabaseStatus = Literal["healthy", "unavailable"]


def check_database(database_url: str) -> DatabaseStatus:
    try:
        with psycopg.connect(
            database_url,
            connect_timeout=2,
            options="-c statement_timeout=2000",
        ) as connection:
            result = connection.execute("SELECT 1").fetchone()
    except Exception:
        return "unavailable"

    return "healthy" if result == (1,) else "unavailable"
