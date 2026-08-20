from types import SimpleNamespace

import pytest

import analyzer.pipeline as pipeline
from analyzer.analysis import AnalysisResult, VERDICT_DANGEROUS, VERDICT_SAFE
from database.models import (
    STATUS_CLEAN,
    STATUS_MALICIOUS,
    THREAT_BOT,
    THREAT_MALWARE,
    THREAT_PHISHING,
    sha256_hex,
)
from database.session import Database

SAFE_EXTERNAL = AnalysisResult(
    url="",
    virustotal={"status": "done", "source": "virustotal", "malicious": 0, "suspicious": 0, "harmless": 9},
    urlhaus={"status": "done", "source": "urlhaus", "found": False},
    google_safebrowsing={"status": "done", "source": "google_safebrowsing", "flagged": False, "threats": []},
)

DANGEROUS_EXTERNAL = AnalysisResult(
    url="",
    virustotal={"status": "done", "source": "virustotal", "malicious": 5, "suspicious": 0, "harmless": 0},
    urlhaus={"status": "done", "source": "urlhaus", "found": True, "threat": "malware_download"},
    google_safebrowsing={"status": "done", "source": "google_safebrowsing", "flagged": True, "threats": ["MALWARE"]},
)


class FakeCache:
    def __init__(self) -> None:
        self.store: dict[str, dict] = {}
        self.writes: list[tuple[str, dict, str]] = []

    def _hits(self, key: str) -> dict | None:
        return self.store.get(key)

    async def get_url(self, url_hash: str) -> dict | None:
        return self._hits(f"url:{url_hash}")

    async def set_url(self, url_hash: str, payload: dict, status: str) -> None:
        self.store[f"url:{url_hash}"] = payload
        self.writes.append((f"url:{url_hash}", payload, status))

    async def get_apk(self, file_hash: str) -> dict | None:
        return self._hits(f"apk:{file_hash}")

    async def set_apk(self, file_hash: str, payload: dict, status: str) -> None:
        self.store[f"apk:{file_hash}"] = payload
        self.writes.append((f"apk:{file_hash}", payload, status))


@pytest.fixture
async def database(tmp_path):
    db = Database(f"sqlite+aiosqlite:///{tmp_path}/pipeline.db")
    await db.connect()
    yield db
    await db.close()


def make_settings() -> SimpleNamespace:
    return SimpleNamespace(request_timeout=10.0)


def make_external(result: AnalysisResult):
    calls: list[str] = []

    async def fake_analyze_url(url, settings) -> AnalysisResult:
        calls.append(url)
        return result

    return calls, fake_analyze_url


# ---------- threat_type / status mapping ----------


def test_threat_type_from_gsb_social_engineering():
    gsb = {"status": "done", "flagged": True, "threats": ["SOCIAL_ENGINEERING"]}
    assert pipeline._threat_type_from(gsb, {}) == THREAT_PHISHING


def test_threat_type_from_gsb_malware():
    gsb = {"status": "done", "flagged": True, "threats": ["MALWARE"]}
    assert pipeline._threat_type_from(gsb, {}) == THREAT_MALWARE


def test_threat_type_from_urlhaus_bot():
    uh = {"status": "done", "found": True, "threat": "c2_botnet"}
    assert pipeline._threat_type_from({}, uh) == THREAT_BOT


def test_threat_type_from_urlhaus_phishing():
    uh = {"status": "done", "found": True, "threat": "phishing_kit"}
    assert pipeline._threat_type_from({}, uh) == THREAT_PHISHING


def test_threat_type_none_when_clean():
    assert pipeline._threat_type_from({"status": "done", "flagged": False, "threats": []}, {}) is None


def test_status_from_verdict():
    assert pipeline.status_from_verdict(VERDICT_DANGEROUS) == STATUS_MALICIOUS
    assert pipeline.status_from_verdict(VERDICT_SAFE) == STATUS_CLEAN


# ---------- check_url pipeline order ----------


async def test_cache_hit_skips_db_and_external(database):
    cache = FakeCache()
    url = "https://cached.example"
    url_hash = sha256_hex(url)
    await cache.set_url(
        url_hash,
        {
            "verdict": "XAVFLI",
            "status": "malicious",
            "threat_type": "phishing",
            "source": "user_report",
            "virustotal": {"status": "done", "source": "virustotal", "malicious": 1},
            "urlhaus": {"status": "skipped", "source": "urlhaus"},
            "google_safebrowsing": {"status": "skipped", "source": "google_safebrowsing"},
        },
        STATUS_MALICIOUS,
    )
    calls, external = make_external(SAFE_EXTERNAL)
    result = await pipeline.check_url(
        url, cache=cache, database=database, settings=make_settings(), external_analyzer=external
    )
    assert result.cached is True
    assert result.status == STATUS_MALICIOUS
    assert result.threat_type == THREAT_PHISHING
    assert calls == []
    assert await database.get_threat_url(url_hash) is not None


async def test_db_hit_skips_external_and_refreshes_cache(database):
    cache = FakeCache()
    url = "https://known.example"
    await database.save_threat_url(
        url=url, domain="known.example", status="malicious", threat_type="bot"
    )
    calls, external = make_external(SAFE_EXTERNAL)
    result = await pipeline.check_url(
        url, cache=cache, database=database, settings=make_settings(), external_analyzer=external
    )
    assert result.cached is True
    assert result.status == STATUS_MALICIOUS
    assert result.threat_type == THREAT_BOT
    assert calls == []
    assert any(key.startswith("url:") for key, _, _ in cache.writes)


async def test_full_flow_dangerous_saves_everywhere(database):
    cache = FakeCache()
    url = "https://evil.example/download"
    calls, external = make_external(DANGEROUS_EXTERNAL)
    result = await pipeline.check_url(
        url, cache=cache, database=database, settings=make_settings(), external_analyzer=external
    )
    assert calls == [url]
    assert result.cached is False
    assert result.status == STATUS_MALICIOUS
    assert result.threat_type == THREAT_MALWARE
    assert result.record_id is not None

    record = await database.get_threat_url(sha256_hex(url))
    assert record is not None
    assert record.status == STATUS_MALICIOUS
    assert record.threat_type == THREAT_MALWARE
    assert record.domain == "evil.example"

    cached = await cache.get_url(sha256_hex(url))
    assert cached is not None
    assert cached["status"] == STATUS_MALICIOUS


async def test_full_flow_clean(database):
    cache = FakeCache()
    url = "https://ok.example"
    calls, external = make_external(SAFE_EXTERNAL)
    result = await pipeline.check_url(
        url, cache=cache, database=database, settings=make_settings(), external_analyzer=external
    )
    assert result.status == STATUS_CLEAN
    assert result.threat_type is None
    record = await database.get_threat_url(sha256_hex(url))
    assert record.status == STATUS_CLEAN
    cached = await cache.get_url(sha256_hex(url))
    assert cached["status"] == STATUS_CLEAN
    assert calls == [url]


async def test_bare_url_normalized_before_hash(database):
    cache = FakeCache()
    url = "example.com/path"
    calls, external = make_external(SAFE_EXTERNAL)
    result = await pipeline.check_url(
        url, cache=cache, database=database, settings=make_settings(), external_analyzer=external
    )
    assert result.url == "https://example.com/path"
    assert calls == ["https://example.com/path"]


async def test_external_error_propagates(database):
    cache = FakeCache()

    async def boom(url, settings):
        raise RuntimeError("api down")

    with pytest.raises(RuntimeError, match="api down"):
        await pipeline.check_url(
            url="https://x.example",
            cache=cache,
            database=database,
            settings=make_settings(),
            external_analyzer=boom,
        )


async def test_database_error_non_fatal(database):
    cache = FakeCache()

    class BrokenDatabase:
        async def get_threat_url(self, url_hash):
            raise RuntimeError("db broken")

        async def save_threat_url(self, **kwargs):
            raise RuntimeError("db broken")

    calls, external = make_external(SAFE_EXTERNAL)
    result = await pipeline.check_url(
        "https://y.example",
        cache=cache,
        database=BrokenDatabase(),
        settings=make_settings(),
        external_analyzer=external,
    )
    assert result.cached is False
    assert result.record_id is None
    assert cache.writes


# ---------- check_apk ----------


async def test_apk_full_flow(database):
    cache = FakeCache()
    data = b"apk-bytes"
    result = await pipeline.check_apk(
        data, "app.apk", cache=cache, database=database, package_name="com.example.app"
    )
    assert result.cached is False
    assert result.status == STATUS_CLEAN
    assert result.file_hash == sha256_hex(data)
    assert await database.get_threat_apk(result.file_hash) is not None
    assert await cache.get_apk(result.file_hash) is not None


async def test_apk_db_hit(database):
    cache = FakeCache()
    data = b"known-bytes"
    await database.save_threat_apk(
        file_hash=sha256_hex(data), file_name="known.apk", status="malicious", malicious_score=77
    )
    result = await pipeline.check_apk(data, "known.apk", cache=cache, database=database)
    assert result.cached is True
    assert result.status == STATUS_MALICIOUS
    assert result.malicious_score == 77
    assert any(key.startswith("apk:") for key, _, _ in cache.writes)


async def test_apk_cache_hit_skips_db(database):
    cache = FakeCache()
    data = b"cached-bytes"
    await cache.set_apk(
        sha256_hex(data), {"file_name": "c.apk", "status": "malicious", "malicious_score": 5}, STATUS_MALICIOUS
    )
    result = await pipeline.check_apk(data, "c.apk", cache=cache, database=database)
    assert result.cached is True
    assert result.malicious_score == 5
    assert await database.get_threat_apk(sha256_hex(data)) is None


async def test_apk_scored_malicious(database):
    cache = FakeCache()
    data = b"score-bytes"
    result = await pipeline.check_apk(data, "bad.apk", cache=cache, database=database, malicious_score=60)
    assert result.status == STATUS_MALICIOUS
    record = await database.get_threat_apk(sha256_hex(data))
    assert record.malicious_score == 60