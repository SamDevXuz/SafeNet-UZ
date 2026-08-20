from types import SimpleNamespace

import pytest

import analyzer.analysis as analysis
from analyzer.analysis import (
    AnalysisResult,
    VERDICT_DANGEROUS,
    VERDICT_SAFE,
    VERDICT_SUSPICIOUS,
    verdict_code,
)


def make_result(vt=None, uh=None, gsb=None) -> AnalysisResult:
    return AnalysisResult(
        url="https://example.com",
        virustotal=vt or {"status": "skipped", "source": "virustotal"},
        urlhaus=uh or {"status": "skipped", "source": "urlhaus"},
        google_safebrowsing=gsb or {"status": "skipped", "source": "google_safebrowsing"},
    )


def test_verdict_code_malicious_viertualtotal():
    vt = {"status": "done", "source": "virustotal", "malicious": 2, "suspicious": 0, "harmless": 0}
    assert verdict_code(vt, {}, {}) == VERDICT_DANGEROUS


def test_verdict_code_urlhaus_found():
    uh = {"status": "done", "source": "urlhaus", "found": True}
    assert verdict_code({}, uh, {}) == VERDICT_DANGEROUS


def test_verdict_code_gsb_flagged():
    gsb = {"status": "done", "source": "google_safebrowsing", "flagged": True, "threats": ["MALWARE"]}
    assert verdict_code({}, {}, gsb) == VERDICT_DANGEROUS


def test_verdict_code_suspicious():
    vt = {"status": "done", "source": "virustotal", "malicious": 0, "suspicious": 3, "harmless": 5}
    assert verdict_code(vt, {}, {}) == VERDICT_SUSPICIOUS


def test_verdict_code_suspicious_not_dangerous_even_with_others_ok():
    vt = {"status": "done", "source": "virustotal", "malicious": 0, "suspicious": 0, "harmless": 9}
    uh = {"status": "done", "source": "urlhaus", "found": False}
    gsb = {"status": "done", "source": "google_safebrowsing", "flagged": False, "threats": []}
    assert verdict_code(vt, uh, gsb) == VERDICT_SAFE


def test_verdict_code_skipped_all_looks_safe():
    assert verdict_code({}, {}, {}) == VERDICT_SAFE


def test_analysis_result_properties():
    res = make_result()
    assert res.is_dangerous is False
    assert res.verdict == VERDICT_SAFE

    res = make_result(
        vt={"status": "done", "source": "virustotal", "malicious": 1, "suspicious": 0, "harmless": 0}
    )
    assert res.is_dangerous is True
    assert res.verdict == VERDICT_DANGEROUS


async def test_analyze_url_creates_service_and_gathers(monkeypatch):
    calls: list[str] = []

    class FakeService:
        async def __aenter__(self) -> "FakeService":
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def check_virustotal_url(self, url: str) -> dict:
            calls.append("virustotal")
            return {"status": "done", "source": "virustotal", "malicious": 0, "suspicious": 0, "harmless": 1}

        async def check_urlhaus(self, url: str) -> dict:
            calls.append("urlhaus")
            return {"status": "done", "source": "urlhaus", "found": False}

        async def check_google_safebrowsing(self, url: str) -> dict:
            calls.append("google_safebrowsing")
            return {"status": "done", "source": "google_safebrowsing", "flagged": False, "threats": []}

    def fake_ctor(**kwargs) -> FakeService:
        seen_kwargs.append(kwargs)
        return FakeService()

    seen_kwargs: list[dict] = []
    monkeypatch.setattr(analysis, "ExternalAPIService", fake_ctor)

    settings = SimpleNamespace(
        virustotal_api_key="vt",
        urlhaus_api_key="uh",
        google_safebrowsing_api_key="gsb",
        request_timeout=5.0,
        heuristics_enabled=False,
        page_probe_enabled=False,
    )
    result = await analysis.analyze_url("https://example.com", settings)
    assert calls == ["virustotal", "urlhaus", "google_safebrowsing"]
    assert result.heuristic == {"level": "none", "flags": []}
    assert seen_kwargs == [
        {
            "virustotal_api_key": "vt",
            "urlhaus_api_key": "uh",
            "google_safebrowsing_api_key": "gsb",
            "timeout": 5.0,
        }
    ]
    assert result.url == "https://example.com"
    assert result.verdict == VERDICT_SAFE


async def test_analyze_url_degrades_on_service_error(monkeypatch):
    class BoomService:
        async def __aenter__(self) -> "BoomService":
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def check_virustotal_url(self, url: str) -> dict:
            raise RuntimeError("network down")

        async def check_urlhaus(self, url: str) -> dict:
            raise RuntimeError("network down")

        async def check_google_safebrowsing(self, url: str) -> dict:
            raise RuntimeError("network down")

    monkeypatch.setattr(analysis, "ExternalAPIService", lambda **kw: BoomService())
    settings = SimpleNamespace(
        virustotal_api_key=None,
        urlhaus_api_key=None,
        google_safebrowsing_api_key=None,
        request_timeout=10.0,
        heuristics_enabled=False,
        page_probe_enabled=False,
    )
    result = await analysis.analyze_url("https://example.com", settings)
    assert result.virustotal["status"] == "error"
    assert result.urlhaus["status"] == "error"
    assert result.google_safebrowsing["status"] == "error"
    assert result.verdict == VERDICT_SAFE

# ---------- verdict heuristic strings ----------


def test_verdict_code_heuristic_dangerous():
    heuristic = {"level": "dangerous", "flags": ["js_capture:getusermedia"]}
    assert verdict_code({}, {}, {}, heuristic) == VERDICT_DANGEROUS


def test_verdict_code_heuristic_suspicious():
    heuristic = {"level": "suspicious", "flags": ["ip_literal_host"]}
    assert verdict_code({}, {}, {}, heuristic) == VERDICT_SUSPICIOUS


def test_verdict_code_heuristic_none_safe():
    heuristic = {"level": "none", "flags": []}
    assert verdict_code({}, {}, {}, heuristic) == VERDICT_SAFE


def test_verdict_code_api_dangerous_beats_safe_heuristic():
    vt = {"status": "done", "malicious": 2}
    heuristic = {"level": "none", "flags": []}
    assert verdict_code(vt, {}, {}, heuristic) == VERDICT_DANGEROUS


def test_verdict_code_heuristic_dangerous_overrides_suspicious_api():
    vt = {"status": "done", "suspicious": 1}
    heuristic = {"level": "dangerous", "flags": ["js_capture:mediadevices"]}
    assert verdict_code(vt, {}, {}, heuristic) == VERDICT_DANGEROUS
