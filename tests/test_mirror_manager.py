from types import SimpleNamespace

import pytest
from aiogram.exceptions import TelegramAPIError

import core.mirror_manager as mm

VALID_TOKEN = "1234567890:AAEaaaBbbCccDddEeeFffGggHhhIiiJjj"
SUCCESS_BODY = {
    "status": "done",
    "username": "mirror_bot",
    "first_name": "Mirror",
    "mode": "polling",
}


class FakeSession:
    async def close(self) -> None:
        return None


class FakeBot:
    def __init__(self, token: str, default=None) -> None:
        self.token = token
        self.session = FakeSession()
        self.me = SimpleNamespace(username="mirror_bot", first_name="Mirror")
        self.calls: list[str] = []
        self.webhook_url: str | None = None

    async def get_me(self):
        self.calls.append("get_me")
        return self.me

    async def set_my_commands(self, commands) -> None:
        self.calls.append("set_my_commands")

    async def set_my_description(self, description) -> None:
        self.calls.append("set_my_description")

    async def set_my_short_description(self, short_description) -> None:
        self.calls.append("set_my_short_description")

    async def set_my_profile_photo(self, photo) -> None:
        self.calls.append("set_my_profile_photo")

    async def set_webhook(self, url) -> None:
        self.calls.append("set_webhook")
        self.webhook_url = url


class FakeDatabase:
    def __init__(self) -> None:
        self.records: list[dict] = []

    async def record_bot(self, **kwargs) -> None:
        self.records.append(kwargs)


@pytest.fixture
def fake_env(monkeypatch):
    monkeypatch.setattr(mm, "Bot", FakeBot)
    db = FakeDatabase()
    monkeypatch.setattr(mm, "get_database", lambda: db)
    monkeypatch.chdir(mm.ASSETS_DIR.parent)
    yield monkeypatch


async def _noop_polling(bot) -> None:
    return None


def make_manager(fake_env, **kwargs) -> mm.MirrorManager:
    return mm.MirrorManager(routers=(), **kwargs)


async def test_invalid_token_raises(fake_env):
    async def failing_get_me(self):
        raise TelegramAPIError(None, "401 Unauthorized")

    fake_env.setattr(FakeBot, "get_me", failing_get_me)
    mgr = make_manager(fake_env)
    with pytest.raises(mm.MirrorSetupError, match="yaroqsiz"):
        await mgr.validate_and_setup_bot(VALID_TOKEN)
    assert mgr.bot_count == 0


async def test_polling_success(fake_env):
    mgr = make_manager(fake_env)
    started: list[str] = []

    async def fake_start(bot) -> None:
        started.append(bot.token)

    mgr._start_polling = fake_start
    result = await mgr.validate_and_setup_bot(VALID_TOKEN)
    assert result == SUCCESS_BODY
    assert started == [VALID_TOKEN]
    assert mgr.is_registered(VALID_TOKEN)
    bot = mgr._bots[VALID_TOKEN]
    assert "set_my_description" in bot.calls
    assert "set_my_short_description" in bot.calls
    assert "set_my_profile_photo" in bot.calls


async def test_duplicate_bot_raises(fake_env):
    mgr = make_manager(fake_env)
    mgr._start_polling = _noop_polling
    await mgr.validate_and_setup_bot(VALID_TOKEN)
    with pytest.raises(mm.MirrorSetupError, match="allaqachon"):
        await mgr.validate_and_setup_bot(VALID_TOKEN)


async def test_branding_error_raises(fake_env):
    async def failing_description(self, description):
        raise TelegramAPIError(None, "400 bad request")

    fake_env.setattr(FakeBot, "set_my_description", failing_description)
    mgr = make_manager(fake_env)
    with pytest.raises(mm.MirrorSetupError, match="profil"):
        await mgr.validate_and_setup_bot(VALID_TOKEN)


async def test_photo_error_is_not_fatal(fake_env):
    async def failing_photo(self, photo):
        raise TelegramAPIError(None, "500")

    fake_env.setattr(FakeBot, "set_my_profile_photo", failing_photo)
    mgr = make_manager(fake_env)
    mgr._start_polling = _noop_polling
    result = await mgr.validate_and_setup_bot(VALID_TOKEN)
    assert result["status"] == "done"


async def test_webhook_mode_sets_webhook(fake_env):
    mgr = make_manager(fake_env, webhook_domain="https://example.com")
    result = await mgr.validate_and_setup_bot(VALID_TOKEN)
    assert result["mode"] == "webhook"
    bot = mgr._bots[VALID_TOKEN]
    assert "set_webhook" in bot.calls
    assert bot.webhook_url == f"https://example.com/webhook/mirror/{VALID_TOKEN}"


async def test_webhook_error_raises(fake_env):
    async def failing_webhook(self, url):
        raise TelegramAPIError(None, "400")

    fake_env.setattr(FakeBot, "set_webhook", failing_webhook)
    mgr = make_manager(fake_env, webhook_domain="https://example.com")
    with pytest.raises(mm.MirrorSetupError, match="Webhook"):
        await mgr.validate_and_setup_bot(VALID_TOKEN)


async def test_register_tokens_from_env_skips_failures(fake_env):
    async def failing_get_me(self):
        raise TelegramAPIError(None, "401")

    fake_env.setattr(FakeBot, "get_me", failing_get_me)
    mgr = make_manager(fake_env)
    mgr._start_polling = _noop_polling
    failure_count = [0]

    async def flaky_get_me(self):
        failure_count[0] += 1
        if failure_count[0] == 1:
            raise TelegramAPIError(None, "401")
        return self.me

    fake_env.setattr(FakeBot, "get_me", flaky_get_me)
    await mgr.register_tokens_from_env(["bad-token", VALID_TOKEN])
    assert mgr.bot_count == 1


async def test_records_bot_in_database(fake_env):
    mgr = make_manager(fake_env)
    mgr._start_polling = _noop_polling
    await mgr.validate_and_setup_bot(VALID_TOKEN)
    db = mm.get_database()
    assert len(db.records) == 1
    assert db.records[0]["bot_token"] == VALID_TOKEN
    assert db.records[0]["username"] == "mirror_bot"
    assert db.records[0]["mode"] == "polling"


async def test_bot_count_and_is_registered(fake_env):
    mgr = make_manager(fake_env)
    mgr._start_polling = _noop_polling
    await mgr.validate_and_setup_bot(VALID_TOKEN)
    assert mgr.bot_count == 1
    assert mgr.is_registered(VALID_TOKEN) is True
    assert mgr.is_registered("other:AAEaaaBbbCccDddEeeFffGggHhhIiiJjj") is False