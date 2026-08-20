import pytest

from analyzer.heuristics import (
    hostname_flags,
    page_flags,
    scan_sync,
)


def test_clean_url_has_no_flags():
    flags, score, level = scan_sync("https://google.com", "google.com", 443)
    assert flags == ()
    assert level == "none"
    assert score == 0


def test_ip_literal_host_is_suspicious():
    flags, score, level = scan_sync(
        "https://185.220.101.4/cam", "185.220.101.4", None
    )
    assert "ip_literal_host" in flags
    assert level == "suspicious"
    assert score == 2


def test_suspicious_tld():
    flags, score, level = scan_sync(
        "http://verify-secure-account.top/login",
        "verify-secure-account.top",
        None,
    )
    assert "suspicious_tld:top" in flags
    assert "keyword:login" in flags
    assert level == "suspicious"


def test_punycode_host():
    flags, score, level = scan_sync(
        "https://xn--80a1a.xn--p1ai/", "xn--80a1a.xn--p1ai", None
    )
    assert "punycode" in flags
    assert level == "suspicious"


def test_keywords_only_match_path_not_domain():
    flags, _, _ = scan_sync("https://google.com/login", "google.com", 443)
    assert "keyword:login" in flags
    flags, _, _ = scan_sync("https://google.com", "google.com", 443)
    assert flags == ()


def test_nonstandard_port():
    flags, _, _ = scan_sync("http://example.com:8080/camera", "example.com", 8080)
    assert "nonstandard_port:8080" in flags
    assert "keyword:camera" in flags


def test_shared_suffix_tld_is_not_filtered():
    flags, _, _ = scan_sync("https://example.com", "example.com", 443)
    assert flags == ()


@pytest.mark.parametrize(
    "host,expected",
    [
        ("185.220.101.4", ("ip_literal_host",)),
        ("xn--80a1a.xn--p1ai", ("punycode",)),
        ("phish.top", ("suspicious_tld:top",)),
        ("example.com", ()),
        ("", ()),
    ],
)
def test_hostname_flags(host, expected):
    assert hostname_flags(host) == expected


def test_page_flags_detect_camera_capture():
    sample = (
        "<html><script>navigator.mediaDevices.getUserMedia({video:true});</script>"
        "<h1>Verify you are human</h1></html>"
    ).lower()
    flags = page_flags(sample)
    assert any(f.startswith("js_capture:") for f in flags)
    assert any(f.startswith("page:") for f in flags)


def test_page_flags_empty_for_clean_page():
    assert page_flags("<html><body>hello world</body></html>") == ()
    assert page_flags(None) == ()