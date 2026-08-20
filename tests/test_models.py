import pytest

from database.models import sha256_hex
from database.session import Database


@pytest.fixture
async def database(tmp_path):
    db = Database(f"sqlite+aiosqlite:///{tmp_path}/threats.db")
    await db.connect()
    yield db
    await db.close()


async def test_save_and_get_threat_url(database):
    record = await database.save_threat_url(
        url="https://evil.example/pay",
        domain="evil.example",
        status="malicious",
        threat_type="phishing",
        source="user_report",
    )
    assert record.id is not None
    assert record.url_hash == sha256_hex("https://evil.example/pay")

    fetched = await database.get_threat_url(record.url_hash)
    assert fetched is not None
    assert fetched.original_url == "https://evil.example/pay"
    assert fetched.status == "malicious"
    assert fetched.threat_type == "phishing"
    assert fetched.domain == "evil.example"


async def test_threat_url_upsert_updates_fields(database):
    await database.save_threat_url(
        url="https://x.example", domain="x.example", status="clean", threat_type=None
    )
    latest = await database.save_threat_url(
        url="https://x.example",
        domain="x.example",
        status="malicious",
        threat_type="malware",
    )
    rows = await database.get_threat_url(sha256_hex("https://x.example"))
    assert rows is not None
    assert rows.id == latest.id
    assert rows.status == "malicious"
    assert rows.threat_type == "malware"


async def test_get_missing_threat_url_returns_none(database):
    assert await database.get_threat_url(sha256_hex("nope")) is None


async def test_sha256_hex_normalized_unique(database):
    plus = sha256_hex("https://a.example")
    minus = sha256_hex("https://A.example")
    assert plus != minus
    assert len(plus) == 64


async def test_save_and_get_threat_apk(database):
    file_hash = sha256_hex(b"fake-apk-bytes")
    record = await database.save_threat_apk(
        file_hash=file_hash,
        file_name="game.apk",
        status="malicious",
        package_name="com.evil.game",
        malicious_score=42,
    )
    assert record.id is not None

    fetched = await database.get_threat_apk(file_hash)
    assert fetched is not None
    assert fetched.file_name == "game.apk"
    assert fetched.package_name == "com.evil.game"
    assert fetched.malicious_score == 42


async def test_threat_apk_upsert_updates_fields(database):
    file_hash = sha256_hex(b"bytes")
    await database.save_threat_apk(
        file_hash=file_hash, file_name="a.apk", status="clean", malicious_score=0
    )
    updated = await database.save_threat_apk(
        file_hash=file_hash,
        file_name="a.apk",
        status="malicious",
        package_name="com.evil.a",
        malicious_score=99,
    )
    fetched = await database.get_threat_apk(file_hash)
    assert fetched.status == "malicious"
    assert fetched.package_name == "com.evil.a"
    assert fetched.malicious_score == 99
    assert fetched.id == updated.id


async def test_apk_url_hash_collision_independent(database):
    same_hash = sha256_hex("hash.example")
    await database.save_threat_url(
        url="hash.example", domain="hash.example", status="clean"
    )
    await database.save_threat_apk(
        file_hash=same_hash, file_name="f.apk", status="clean"
    )
    url_row = await database.get_threat_url(same_hash)
    apk_row = await database.get_threat_apk(same_hash)
    assert url_row is not None and apk_row is not None
    assert url_row.original_url == "hash.example"
    assert apk_row.file_name == "f.apk"