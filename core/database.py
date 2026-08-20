import hashlib
import logging
from datetime import datetime, timezone
from typing import Any

import aiosqlite

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS mirror_bots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT UNIQUE NOT NULL,
    username TEXT,
    first_name TEXT,
    mode TEXT NOT NULL DEFAULT 'polling',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    hostname TEXT,
    verdict TEXT,
    source_bot_username TEXT,
    created_at TEXT NOT NULL
);
"""


def hash_token(bot_token: str) -> str:
    return hashlib.sha256(bot_token.encode()).hexdigest()


class Database:
    def __init__(self, path: str) -> None:
        self._path = path
        self._conn: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        self._conn = await aiosqlite.connect(self._path)
        await self._conn.execute("PRAGMA journal_mode=WAL;")
        await self._conn.executescript(_SCHEMA)
        await self._conn.commit()
        logger.info("Database tayyor: %s", self._path)

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    @property
    def _connection(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("Database ulanmagan: connect() chaqirilmagan")
        return self._conn

    async def record_bot(
        self, bot_token: str, username: str | None, first_name: str | None, mode: str
    ) -> None:
        await self._connection.execute(
            """
            INSERT INTO mirror_bots (token_hash, username, first_name, mode, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(token_hash) DO UPDATE SET
                username = excluded.username,
                first_name = excluded.first_name,
                mode = excluded.mode
            """,
            (
                hash_token(bot_token),
                username,
                first_name,
                mode,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        await self._connection.commit()

    async def list_bots(self) -> list[dict[str, Any]]:
        cursor = await self._connection.execute(
            "SELECT token_hash, username, first_name, mode, created_at FROM mirror_bots"
        )
        rows = await cursor.fetchall()
        await cursor.close()
        return [
            {
                "token_hash": row[0],
                "username": row[1],
                "first_name": row[2],
                "mode": row[3],
                "created_at": row[4],
            }
            for row in rows
        ]

    async def remove_bot(self, token_hash: str) -> None:
        await self._connection.execute(
            "DELETE FROM mirror_bots WHERE token_hash = ?", (token_hash,)
        )
        await self._connection.commit()

    async def record_analysis(
        self,
        url: str,
        hostname: str,
        verdict: str,
        source_bot_username: str | None = None,
    ) -> None:
        await self._connection.execute(
            """
            INSERT INTO analyses (url, hostname, verdict, source_bot_username, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                url,
                hostname,
                verdict,
                source_bot_username,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        await self._connection.commit()

    async def count_analyses(self) -> int:
        cursor = await self._connection.execute("SELECT COUNT(*) FROM analyses")
        row = await cursor.fetchone()
        await cursor.close()
        return int(row[0]) if row else 0


_database: Database | None = None


def init_database(path: str) -> Database:
    global _database
    _database = Database(path)
    return _database


def get_database() -> Database:
    if _database is None:
        raise RuntimeError("Database hali boshlanmagan: init_database() chaqirilmagan")
    return _database