import pytest

import bot.handlers.mirror as mirror_module
from core.mirror_manager import MirrorSetupError

VALID_TOKEN = "1234567890:AAEaaaBbbCccDddEeeFffGggHhhIiiJjj"


@pytest.fixture(autouse=True)
def clear_pending():
    mirror_module._pending_users.clear()
    yield
    mirror_module._pending_users.clear()


class FakeManager:
    def __init__(self) -> None:
        self.setup_calls: list[str] = []
        self.error: MirrorSetupError | None = None
        self.result = {
            "status": "done",
            "username": "mirror_bot",
            "first_name": "Mirror",
            "mode": "polling",
        }

    async def validate_and_setup_bot(self, token: str) -> dict:
        self.setup_calls.append(token)
        if self.error:
            raise self.error
        return self.result


@pytest.fixture
def fake_manager(monkeypatch):
    manager = FakeManager()
    monkeypatch.setattr(mirror_module, "get_mirror_manager", lambda: manager)
    return manager


async def test_addbot_command_starts_flow(make_message):
    message = make_message(text="/addbot")
    await mirror_module.add_bot(message)
    assert message.from_user.id in mirror_module._pending_users
    assert len(message.replies) == 1
    assert "tokeningizni kiriting" in message.replies[0][0]


async def test_token_ignored_when_not_pending(make_message):
    message = make_message(text=VALID_TOKEN)
    await mirror_module.handle_bot_token(message)
    assert message.replies == []
    assert message.edits == []


async def test_invalid_token_format_rejected(make_message):
    message = make_message(text="/addbot")
    await mirror_module.add_bot(message)
    invalid = make_message(text="not-a-token")
    await mirror_module.handle_bot_token(invalid)
    assert len(invalid.replies) == 1
    assert "formati noto'g'ri" in invalid.replies[0][0]
    assert message.from_user.id in mirror_module._pending_users


async def test_valid_token_setup_success(make_message, fake_manager):
    message = make_message(text="/addbot")
    await mirror_module.add_bot(message)
    token_msg = make_message(text=VALID_TOKEN)
    await mirror_module.handle_bot_token(token_msg)
    assert fake_manager.setup_calls == [VALID_TOKEN]
    assert len(token_msg.replies) == 1
    assert "tekshirilmoqda" in token_msg.replies[0][0]
    assert len(token_msg.edits) == 1
    report = token_msg.edits[0][0]
    assert "muvaffaqiyatli SafeNet UZ tarmog'iga ulandi" in report
    assert "@mirror_bot" in report
    assert "Polling rejim" in report
    assert message.from_user.id not in mirror_module._pending_users


async def test_setup_error_reported(make_message, fake_manager):
    fake_manager.error = MirrorSetupError("Token yaroqsiz. Iltimos, tekshiring.")
    message = make_message(text="/addbot")
    await mirror_module.add_bot(message)
    token_msg = make_message(text=VALID_TOKEN)
    await mirror_module.handle_bot_token(token_msg)
    assert len(token_msg.edits) == 1
    assert "Token yaroqsiz" in token_msg.edits[0][0]
    assert message.from_user.id not in mirror_module._pending_users


async def test_success_webhook_mode_text(make_message, fake_manager):
    fake_manager.result["mode"] = "webhook"
    message = make_message(text="/addbot")
    await mirror_module.add_bot(message)
    token_msg = make_message(text=VALID_TOKEN)
    await mirror_module.handle_bot_token(token_msg)
    report = token_msg.edits[0][0]
    assert "Webhook rejim" in report