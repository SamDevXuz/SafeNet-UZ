import pytest

from core.webhook import process_webhook_payload


class FakeManager:
    def __init__(self) -> None:
        self.registered = {"tok:fake"}
        self.deliveries: list[tuple[str, object]] = []

    def is_registered(self, token: str) -> bool:
        return token in self.registered

    async def feed_update(self, token: str, update) -> bool:
        self.deliveries.append((token, update))
        return True


@pytest.mark.asyncio
async def test_unknown_bot_is_rejected() -> None:
    manager = FakeManager()
    result = await process_webhook_payload(manager, "nope:bad", {"update_id": 1})
    assert result == {"ok": False, "error": "unknown bot"}


@pytest.mark.asyncio
async def test_valid_update_is_delivered() -> None:
    manager = FakeManager()
    payload = {
        "update_id": 1,
        "message": {
            "message_id": 7,
            "date": 1700000000,
            "chat": {"id": 42, "type": "private", "first_name": "Tester"},
            "from": {"id": 42, "first_name": "Tester", "is_bot": False},
            "text": "/start",
        },
    }
    result = await process_webhook_payload(manager, "tok:fake", payload)
    assert result == {"ok": True, "delivered": True}
    delivered_token, update = manager.deliveries[0]
    assert delivered_token == "tok:fake"
    assert update.update_id == 1
    assert update.message.text == "/start"