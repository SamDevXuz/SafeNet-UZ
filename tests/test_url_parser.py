from analyzer.url_parser import parse_url


def test_full_url_with_port_query():
    parsed = parse_url("https://example.com:8080/path?q=1&r=2#frag")
    assert parsed.raw == "https://example.com:8080/path?q=1&r=2#frag"
    assert parsed.scheme == "https"
    assert parsed.hostname == "example.com"
    assert parsed.port == 8080
    assert parsed.path == "/path"
    assert parsed.query == "q=1&r=2"
    assert parsed.is_https is True


def test_bare_domain_gets_https():
    parsed = parse_url("example.com/login")
    assert parsed.scheme == "https"
    assert parsed.hostname == "example.com"
    assert parsed.is_https is True


def test_www_without_scheme():
    parsed = parse_url("www.example.com")
    assert parsed.scheme == "https"
    assert parsed.hostname == "www.example.com"
    assert parsed.is_https is True


def test_http_not_https():
    parsed = parse_url("http://example.com")
    assert parsed.scheme == "http"
    assert parsed.is_https is False


def test_case_insensitive_scheme():
    parsed = parse_url("HTTPS://Example.com/Path")
    assert parsed.scheme == "https"
    assert parsed.hostname.lower() == "example.com"


def test_empty_hostname():
    parsed = parse_url("ftp://")
    assert parsed.scheme == "ftp"
    assert parsed.hostname == ""
    assert parsed.is_https is False


def test_ipv4_host():
    parsed = parse_url("http://192.168.1.1/admin")
    assert parsed.hostname == "192.168.1.1"