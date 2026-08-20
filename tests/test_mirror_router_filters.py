import pytest
from aiogram.types import Chat, Message, User

from bot.handlers.mirror import _OnlyPendingFilter, _pending_users


def _message(user_id: int, text: str = "https://example.com") -> Message:
    user = User(id=user_id, is_bot=False, first_name="Tester")
    chat = Chat(id=user_id, type="private", first_name="Tester")
    return Message(message_id=1, date=1700000000, chat=chat, from_user=user, text=text)


@pytest.mark.asyncio
async def test_pending_filter_skips_regular_users() -> None:
    _pending_users.clear()
    filt = _OnlyPendingFilter()
    assert await filt(_message(user_id=42)) is False


@pytest.mark.asyncio
async def test_pending_filter_matches_pending_users() -> None:
    _pending_users.clear()
    _pending_users.add(42)
    try:
        filt = _OnlyPendingFilter()
        assert await filt(_message(user_id=42)) is True
    finally:
        _pending_users.clear()