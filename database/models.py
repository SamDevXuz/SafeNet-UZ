import hashlib
from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

STATUS_CLEAN = "clean"
STATUS_MALICIOUS = "malicious"

THREAT_PHISHING = "phishing"
THREAT_MALWARE = "malware"
THREAT_BOT = "bot"

SOURCE_USER_REPORT = "user_report"
SOURCE_EXTERNAL_API = "external_api"


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def sha256_hex(text: str | bytes) -> str:
    if isinstance(text, str):
        text = text.encode("utf-8")
    return hashlib.sha256(text).hexdigest()


hash_token = sha256_hex


class Base(DeclarativeBase):
    pass


class MirrorBot(Base):
    __tablename__ = "mirror_bots"

    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    username: Mapped[str | None] = mapped_column(String(255))
    first_name: Mapped[str | None] = mapped_column(String(255))
    mode: Mapped[str] = mapped_column(String(16), default="polling")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc
    )


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(primary_key=True)
    url: Mapped[str] = mapped_column(Text)
    hostname: Mapped[str | None] = mapped_column(String(255))
    verdict: Mapped[str | None] = mapped_column(String(16))
    source_bot_username: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc
    )


class ThreatURL(Base):
    __tablename__ = "threat_urls"

    id: Mapped[int] = mapped_column(primary_key=True)
    url_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    original_url: Mapped[str] = mapped_column(Text)
    domain: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16))
    threat_type: Mapped[str | None] = mapped_column(String(16))
    source: Mapped[str] = mapped_column(String(32), default=SOURCE_USER_REPORT)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc, onupdate=now_utc
    )


class ThreatAPK(Base):
    __tablename__ = "threat_apks"

    id: Mapped[int] = mapped_column(primary_key=True)
    file_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    file_name: Mapped[str] = mapped_column(String(255))
    package_name: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16))
    malicious_score: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc, onupdate=now_utc
    )