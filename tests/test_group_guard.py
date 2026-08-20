import asyncio
from types import SimpleNamespace

import pytest

import bot.handlers.group_guard as guard
from analyzer.analysis import AnalysisResult
from analyzer.url_parser import URL_RE

DANGEROUS_VT = {"status": "done", "source": "virustotal", "malicious": 4, "suspicious": 0, "harmless": 0}
SAFE_RESULT = AnalysisResult(
    url="https://example.com",
    virustotal={"status": "done", "source": "virustotal", "malicious": 0, "suspicious": 0, "harmless": 9},
    urlhaus={"status": "done", "source": "urlhaus", "found": False},
    google_safebrowsing={"status": "done", "source": "google_safebrowsing", "flagged": False, "threats": []},
)


@pytest.fixture
def fake_settings(monkeypatch):
    overrides: dict = {}

    def get() -> SimpleNamespace:
        defaults = {
            "virustotal_api_key": None,
            "urlhaus_api_key": None,
            "google_safebrowsing_api_key": None,
            "request_timeout": 10.0,
            "group_guard_block_apk": True,
            "group_guard_warning_ttl": 0.02,
        }
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    monkeypatch.setattr(guard, "get_settings", get)

    def set_overrides(**kw: object) -> None:
        overrides.update(kw)

    return set_overrides


@pytest.fixture
def fake_analyzer(monkeypatch):
    calls: list[str] = []

    async def fake_analyze_url(url, settings) -> AnalysisResult:
        calls.append(url)
        return SAFE_RESULT

    monkeypatch.setattr(guard, "analyze_url", fake_analyze_url)
    return calls


@pytest.fixture
def background_tasks():
    prev = list(guard._background)
    yield prev
    guard._background.clear()


async def _drain_background() -> None:
    for _ in range(50):
        if not guard._background:
            await asyncio.sleep(0.005)
            break
        await asyncio.sleep(0.005)
    await asyncio.sleep(0.05)


def test_detect_threat_url(make_message):
    msg = make_message(text="salom https://evil.example/x apk o'rnatmang")
    threat = guard._detect_threat(msg)
    assert threat == {"url": "https://evil.example/x", "apk": False, "mention": False}


def test_detect_threat_apk_document(make_message):
    msg = make_message(text="", document=SimpleNamespace(file_name="game.apk"))
    threat = guard._detect_threat(msg)
    assert threat["url"] is None
    assert threat["apk"] is True


def test_detect_threat_uppercase_apk(make_message):
    msg = make_message(text="", document=SimpleNamespace(file_name="PLAY.APK"))
    assert guard._detect_threat(msg)["apk"] is True


def test_detect_threat_tg_mention(make_message):
    msg = make_message(text="@scam_bot kanalga kiring")
    threat = guard._detect_threat(msg)
    assert threat["url"] is None
    assert threat["apk"] is False
    assert threat["mention"] is True


def test_detect_threat_clean_message(make_message):
    msg = make_message(text="oddiy xabar")
    assert guard._detect_threat(msg) is None


def test_escape_md():
    assert guard._escape_md("a_b *c* [x]") == r"a\_b \*c\* \[x\]"


async def test_clean_message_not_deleted(make_message, fake_settings, fake_analyzer, background_tasks):
    msg = make_message(text="oddiy xabar")
    await guard.guard_group_message(msg)
    await _drain_background()
    assert msg.deleted is False
    assert msg.replies == []
    assert fake_analyzer == []


async def test_dangerous_url_deleted_and_warned(make_message, fake_settings, fake_analyzer, monkeypatch):
    async def bad_analyze(url, settings) -> AnalysisResult:
        return AnalysisResult(
            url=url,
            virustotal=DANGEROUS_VT,
            urlhaus={"status": "skipped", "source": "urlhaus"},
            google_safebrowsing={"status": "skipped", "source": "google_safebrowsing"},
        )

    monkeypatch.setattr(guard, "analyze_url", bad_analyze)
    msg = make_message(text="https://phishing.example/pay")
    await guard.guard_group_message(msg)
    await _drain_background()
    assert msg.deleted is True
    assert len(msg.replies) == 1
    warning_text = msg.replies[0][0]
    assert "DIQQAT: FIRIBGARLIK (PHISHING)!" in warning_text
    assert "Test User" in warning_text
    assert "xavfli deb topildi" in warning_text
    assert "o'chirildi" in warning_text
    await asyncio.sleep(0.02 + 0.05)
    assert msg.replies  # warning was sent
    assert msg.edits == []


async def test_safe_url_not_deleted(make_message, fake_settings, fake_analyzer):
    msg = make_message(text="https://example.com nice site")
    await guard.guard_group_message(msg)
    await _drain_background()
    assert msg.deleted is False
    assert msg.replies == []


async def test_apk_deleted_when_block_enabled(make_message, fake_settings, fake_analyzer):
    fake_settings(group_guard_block_apk=True)
    msg = make_message(text="", document=SimpleNamespace(file_name="virus.apk"))
    await guard.guard_group_message(msg)
    await _drain_background()
    assert msg.deleted is True
    assert len(msg.replies) == 1
    assert "yuborgan havola/fayl xavfli deb topildi" in msg.replies[0][0]


async def test_apk_not_deleted_when_block_disabled(make_message, fake_settings, fake_analyzer):
    fake_settings(group_guard_block_apk=False)
    msg = make_message(text="", document=SimpleNamespace(file_name="legit.apk"))
    await guard.guard_group_message(msg)
    await _drain_background()
    assert msg.deleted is False
    assert msg.replies == []


async def test_mention_only_not_deleted(make_message, fake_settings, fake_analyzer):
    msg = make_message(text="@telegram_bot tavsiya")
    await guard.guard_group_message(msg)
    await _drain_background()
    assert msg.deleted is False
    assert msg.replies == []
    assert fake_analyzer == []


def test_url_regex_exported_from_parser():
    assert URL_RE is guard.URL_RE or URL_RE.pattern == guard.URL_RE.pattern