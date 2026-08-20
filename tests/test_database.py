import pytest

from core.database import Database, hash_token


@pytest.fixture
async def database(tmp_path):
    db = Database(str(tmp_path / "test.db"))
    await db.connect()
    yield db
    await db.close()


async def test_hash_token_is_sha256():
    h = hash_token("1234567890:AAE-test-token")
    assert len(h) == 64
    assert hash_token("abc") != hash_token("abd")


async def test_record_and_list_bot(database):
    await database.record_bot("1234567890:AAE-test", "@mymirror", "My Mirror", "polling")
    bots = await database.list_bots()
    assert len(bots) == 1
    bot = bots[0]
    assert bot["token_hash"] == hash_token("1234567890:AAE-test")
    assert bot["username"] == "@mymirror"
    assert bot["mode"] == "polling"
    assert bot["created_at"]


async def test_record_bot_upsert(database):
    await database.record_bot("tok", "@a", "A", "polling")
    await database.record_bot("tok", "@b", "B", "webhook")
    bots = await database.list_bots()
    assert len(bots) == 1
    assert bots[0]["username"] == "@b"
    assert bots[0]["mode"] == "webhook"


async def test_remove_bot(database):
    await database.record_bot("tok", "@a", "A", "polling")
    await database.remove_bot(hash_token("tok"))
    assert await database.list_bots() == []


async def test_record_and_count_analyses(database):
    assert await database.count_analyses() == 0
    await database.record_analysis("https://evil.example/x", "evil.example", "XAVFLI", "@mirror")
    await database.record_analysis("https://ok.example", "ok.example", "XAVFSIZ")
    assert await database.count_analyses() == 2


async def test_unconnected_db_raises(tmp_path):
    db = Database(str(tmp_path / "new.db"))
    with pytest.raises(RuntimeError):
        await db.record_bot("tok", "@a", "A", "polling")