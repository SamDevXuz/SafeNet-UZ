import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from database.models import (
    Analysis,
    Base,
    MirrorBot,
    ThreatAPK,
    ThreatURL,
    sha256_hex,
)

logger = logging.getLogger(__name__)


class Database:
    def __init__(self, url: str) -> None:
        self._url = url
        self._engine: AsyncEngine | None = None
        self._factory: async_sessionmaker[AsyncSession] | None = None

    async def connect(self) -> None:
        self._engine = create_async_engine(self._url)
        self._factory = async_sessionmaker(self._engine, expire_on_commit=False)
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tayyor: %s", self._url)

    async def close(self) -> None:
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None
            self._factory = None

    @property
    def engine(self) -> AsyncEngine:
        if self._engine is None:
            raise RuntimeError("Database ulanmagan: connect() chaqirilmagan")
        return self._engine

    @property
    def factory(self) -> async_sessionmaker[AsyncSession]:
        if self._factory is None:
            raise RuntimeError("Database ulanmagan: connect() chaqirilmagan")
        return self._factory

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        async with self.factory() as session:
            yield session

    # ---------- mirror_bots ----------

    async def record_bot(
        self, bot_token: str, username: str | None, first_name: str | None, mode: str
    ) -> None:
        token_hash = sha256_hex(bot_token)
        async with self.session() as session:
            bot = await session.scalar(
                select(MirrorBot).where(MirrorBot.token_hash == token_hash)
            )
            if bot is None:
                session.add(
                    MirrorBot(
                        token_hash=token_hash,
                        username=username,
                        first_name=first_name,
                        mode=mode,
                    )
                )
            else:
                if username is not None:
                    bot.username = username
                if first_name is not None:
                    bot.first_name = first_name
                bot.mode = mode
            await session.commit()

    async def list_bots(self) -> list[dict[str, Any]]:
        async with self.session() as session:
            rows = (
                await session.scalars(select(MirrorBot).order_by(MirrorBot.id))
            ).all()
        return [
            {
                "token_hash": row.token_hash,
                "username": row.username,
                "first_name": row.first_name,
                "mode": row.mode,
                "created_at": row.created_at.isoformat() if row.created_at else "",
            }
            for row in rows
        ]

    async def remove_bot(self, token_hash: str) -> None:
        async with self.session() as session:
            await session.execute(
                delete(MirrorBot).where(MirrorBot.token_hash == token_hash)
            )
            await session.commit()

    # ---------- analyses ----------

    async def record_analysis(
        self,
        url: str,
        hostname: str,
        verdict: str,
        source_bot_username: str | None = None,
    ) -> None:
        async with self.session() as session:
            session.add(
                Analysis(
                    url=url,
                    hostname=hostname,
                    verdict=verdict,
                    source_bot_username=source_bot_username,
                )
            )
            await session.commit()

    async def count_analyses(self) -> int:
        async with self.session() as session:
            return int(
                await session.scalar(select(func.count()).select_from(Analysis)) or 0
            )

    # ---------- threat_urls ----------

    async def get_threat_url(self, url_hash: str) -> ThreatURL | None:
        async with self.session() as session:
            return await session.scalar(
                select(ThreatURL).where(ThreatURL.url_hash == url_hash)
            )

    async def save_threat_url(
        self,
        *,
        url: str,
        domain: str | None,
        status: str,
        threat_type: str | None = None,
        source: str = "user_report",
    ) -> ThreatURL:
        url_hash = sha256_hex(url)
        async with self.session() as session:
            record = await session.scalar(
                select(ThreatURL).where(ThreatURL.url_hash == url_hash)
            )
            if record is None:
                record = ThreatURL(
                    url_hash=url_hash,
                    original_url=url,
                    domain=domain,
                    status=status,
                    threat_type=threat_type,
                    source=source,
                )
                session.add(record)
            else:
                record.original_url = url
                record.domain = domain
                record.status = status
                record.threat_type = threat_type
                record.source = source
            await session.commit()
            await session.refresh(record)
            return record

    # ---------- threat_apks ----------

    async def get_threat_apk(self, file_hash: str) -> ThreatAPK | None:
        async with self.session() as session:
            return await session.scalar(
                select(ThreatAPK).where(ThreatAPK.file_hash == file_hash)
            )

    async def save_threat_apk(
        self,
        *,
        file_hash: str,
        file_name: str,
        status: str,
        package_name: str | None = None,
        malicious_score: int = 0,
    ) -> ThreatAPK:
        async with self.session() as session:
            record = await session.scalar(
                select(ThreatAPK).where(ThreatAPK.file_hash == file_hash)
            )
            if record is None:
                record = ThreatAPK(
                    file_hash=file_hash,
                    file_name=file_name,
                    package_name=package_name,
                    status=status,
                    malicious_score=malicious_score,
                )
                session.add(record)
            else:
                record.file_name = file_name
                record.package_name = package_name
                record.status = status
                record.malicious_score = malicious_score
            await session.commit()
            await session.refresh(record)
            return record


_database: Database | None = None


def init_database(url: str) -> Database:
    global _database
    _database = Database(url)
    return _database


def get_database() -> Database:
    if _database is None:
        raise RuntimeError("Database hali boshlanmagan: init_database() chaqirilmagan")
    return _database