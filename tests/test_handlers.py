import bot.handlers.analyze as analyze_module
import bot.handlers.start as start_module
from analyzer.analysis import verdict_code
from analyzer.pipeline import URLScanResult, status_from_verdict
from bot.handlers.analyze import _URL_RE, format_report


SKIPPED_VT = {"status": "skipped", "source": "virustotal"}
SKIPPED_UH = {"status": "skipped", "source": "urlhaus"}
SKIPPED_GSB = {"status": "skipped", "source": "google_safebrowsing"}

DANGEROUS_VT = {"status": "done", "source": "virustotal", "malicious": 3, "suspicious": 1, "harmless": 7}


def _patch_settings(monkeypatch, make_settings) -> None:
    monkeypatch.setattr(analyze_module, "get_settings", make_settings)


def _patch_service(monkeypatch, results: dict) -> None:
    async def fake_check_url(url, *, cache=None, database=None, settings=None, source="user_report"):
        return URLScanResult(
            url=url,
            verdict=verdict_code(results["virustotal"], results["urlhaus"], results["google_safebrowsing"]),
            status=status_from_verdict(
                verdict_code(results["virustotal"], results["urlhaus"], results["google_safebrowsing"])
            ),
            threat_type=None,
            source=source,
            cached=False,
            virustotal=results["virustotal"],
            urlhaus=results["urlhaus"],
            google_safebrowsing=results["google_safebrowsing"],
        )

    monkeypatch.setattr(analyze_module, "pipeline_check_url", fake_check_url)


# ---------- start handler ----------


async def test_start_command_reply(make_message):
    message = make_message()
    await start_module.cmd_start(message)
    assert len(message.replies) == 1
    text, _ = message.replies[0]
    assert "SafeNet UZ" in text


# ---------- format_report ----------


def test_format_report_all_skipped():
    report = format_report("https://example.com", "example.com", SKIPPED_VT, SKIPPED_UH, SKIPPED_GSB)
    assert "O'tkazib yuborildi" in report
    assert "XAVFSIZ" in report


def test_format_report_malicious_verdict():
    vt = {"status": "done", "source": "virustotal", "malicious": 12, "suspicious": 3, "harmless": 1}
    report = format_report("https://evil.com/x", "evil.com", vt, SKIPPED_UH, SKIPPED_GSB)
    assert "*Malicious:* `12`" in report
    assert "XAVFLI" in report


def test_format_report_suspicious_verdict():
    vt = {"status": "done", "source": "virustotal", "malicious": 0, "suspicious": 4, "harmless": 5}
    report = format_report("https://susp.com", "susp.com", vt, SKIPPED_UH, SKIPPED_GSB)
    assert "SHUBHALI" in report


def test_format_report_clear_verdict_when_all_done():
    vt = {"status": "done", "source": "virustotal", "malicious": 0, "suspicious": 0, "harmless": 42}
    uh = {"status": "done", "source": "urlhaus", "found": False}
    gsb = {"status": "done", "source": "google_safebrowsing", "flagged": False, "threats": []}
    report = format_report("https://ok.example", "ok.example", vt, uh, gsb)
    assert "topilmadi" in report
    assert "aniqlanmadi" in report
    assert "XAVFSIZ" in report


def test_format_report_urlhaus_flag_wins():
    vt = {"status": "done", "source": "virustotal", "malicious": 0, "suspicious": 0, "harmless": 1}
    uh = {
        "status": "done",
        "source": "urlhaus",
        "found": True,
        "threat": "malware_download",
        "blacklist_count": 2,
    }
    report = format_report("https://maldist.example", "maldist.example", vt, uh, SKIPPED_GSB)
    assert "malware_download" in report
    assert "XAVFLI" in report


def test_format_report_gsb_flag_wins():
    vt = {"status": "done", "source": "virustotal", "malicious": 0, "suspicious": 0, "harmless": 2}
    gsb = {
        "status": "done",
        "source": "google_safebrowsing",
        "flagged": True,
        "threats": ["MALWARE", "UNWANTED_SOFTWARE"],
    }
    report = format_report("https://bad.example", "bad.example", vt, SKIPPED_UH, gsb)
    assert "MALWARE" in report
    assert "UNWANTED_SOFTWARE" in report
    assert "XAVFLI" in report


def test_format_report_error_branches():
    err_vt = {"status": "error", "source": "virustotal", "reason": "network"}
    report = format_report("https://x.example", "x.example", err_vt, SKIPPED_UH, SKIPPED_GSB)
    assert "Tekshirilmadi" in report
    assert "XAVFSIZ" in report


def test_format_report_contains_hostname_and_url():
    report = format_report(
        "https://example.com:8443/a?b=1", "example.com", SKIPPED_VT, SKIPPED_UH, SKIPPED_GSB
    )
    assert "https://example.com:8443/a?b=1" in report
    assert "example.com" in report


# ---------- analyze handler ----------


async def test_analyze_no_url_replies_hint(make_message, monkeypatch, make_settings):
    _patch_settings(monkeypatch, make_settings)
    message = make_message(text="salom, bu yerda havola yo'q")
    await analyze_module.analyze_url(message)
    assert len(message.replies) == 1
    assert "Havola topilmadi" in message.replies[0][0]
    assert message.edits == []


async def test_analyze_https_url_full_flow(make_message, monkeypatch, make_settings):
    _patch_settings(monkeypatch, make_settings)
    results = {
        "virustotal": {"status": "done", "source": "virustotal", "malicious": 3, "suspicious": 1, "harmless": 7},
        "urlhaus": {"status": "skipped", "source": "urlhaus"},
        "google_safebrowsing": {"status": "skipped", "source": "google_safebrowsing"},
    }
    _patch_service(monkeypatch, results)
    message = make_message(text="shuni tekshir https://example.com/login")
    await analyze_module.analyze_url(message)
    assert len(message.replies) == 1
    assert "Tahlil boshlandi" in message.replies[0][0]
    assert len(message.edits) == 1
    report, parse_mode = message.edits[0]
    assert parse_mode == "Markdown"
    assert "example.com" in report
    assert "XAVFLI" in report


async def test_analyze_www_url_without_scheme(make_message, monkeypatch, make_settings):
    _patch_settings(monkeypatch, make_settings)
    results = {
        "virustotal": SKIPPED_VT,
        "urlhaus": SKIPPED_UH,
        "google_safebrowsing": SKIPPED_GSB,
    }
    _patch_service(monkeypatch, results)
    message = make_message(text="www.shubhali.uz/enter")
    await analyze_module.analyze_url(message)
    assert len(message.edits) == 1
    assert "www.shubhali.uz" in message.edits[0][0]


async def test_analyze_caption_url(make_message, monkeypatch, make_settings):
    _patch_settings(monkeypatch, make_settings)
    results = {
        "virustotal": SKIPPED_VT,
        "urlhaus": SKIPPED_UH,
        "google_safebrowsing": SKIPPED_GSB,
    }
    _patch_service(monkeypatch, results)
    message = make_message(caption="foto tagida: https://t.me/fake_channel")
    await analyze_module.analyze_url(message)
    assert len(message.edits) == 1
    assert "t.me" in message.edits[0][0]


async def test_analyze_unexpected_error_shows_warning(make_message, monkeypatch, make_settings):
    _patch_settings(monkeypatch, make_settings)

    async def boom_check(url, **kwargs) -> URLScanResult:
        raise RuntimeError("boom")

    monkeypatch.setattr(analyze_module, "pipeline_check_url", boom_check)
    message = make_message(text="https://example.com")
    await analyze_module.analyze_url(message)
    assert len(message.edits) == 1
    assert "kutilmagan xatolik" in message.edits[0][0]


def test_analyze_url_regex_matches():
    assert _URL_RE.search("https://example.com/x") is not None
    assert _URL_RE.search("http://example.com") is not None
    assert _URL_RE.search("www.example.com/x") is not None
    assert _URL_RE.search("ttps://no.com") is None
    assert _URL_RE.search("https://") is None