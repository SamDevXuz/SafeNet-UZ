from types import SimpleNamespace

import pytest


def default_user() -> SimpleNamespace:
    return SimpleNamespace(
        id=1, username="test_user", first_name="Test", full_name="Test User"
    )


class FakeMessage:
    def __init__(
        self,
        text: str | None = None,
        caption: str | None = None,
        from_user: object | None = None,
        document: object | None = None,
        chat: object | None = None,
    ) -> None:
        self.text = text
        self.caption = caption
        self.from_user = from_user if from_user is not None else default_user()
        self.document = document
        self.chat = chat if chat is not None else SimpleNamespace(id=-100123, type="group")
        self.deleted = False
        self.replies: list[tuple[str, str | None]] = []
        self.edits: list[tuple[str, str | None]] = []

    async def answer(
        self, text: str, parse_mode: str | None = None, **kwargs: object
    ) -> "FakeMessage":
        self.replies.append((text, parse_mode))
        return self

    async def edit_text(
        self, text: str, parse_mode: str | None = None, **kwargs: object
    ) -> None:
        self.edits.append((text, parse_mode))

    async def delete(self) -> None:
        self.deleted = True


class FakeExternalAPIService:
    def __init__(self, results: dict) -> None:
        self.results = results

    async def __aenter__(self) -> "FakeExternalAPIService":
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    async def check_virustotal_url(self, url: str) -> dict:
        return self.results["virustotal"]

    async def check_urlhaus(self, url: str) -> dict:
        return self.results["urlhaus"]

    async def check_google_safebrowsing(self, url: str) -> dict:
        return self.results["google_safebrowsing"]


@pytest.fixture
def make_message():
    def _make(text: str | None = None, caption: str | None = None, **kwargs: object) -> FakeMessage:
        return FakeMessage(text=text, caption=caption, **kwargs)

    return _make


@pytest.fixture
def make_api_service():
    def _make(results: dict) -> FakeExternalAPIService:
        return FakeExternalAPIService(results)

    return _make


@pytest.fixture
def make_settings():
    def _make(**overrides: object) -> SimpleNamespace:
        defaults: dict[str, object] = {
            "bot_token": "123:test",
            "log_level": "INFO",
            "request_timeout": 10.0,
            "virustotal_api_key": None,
            "urlhaus_api_key": None,
            "google_safebrowsing_api_key": None,
        }
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    return _make