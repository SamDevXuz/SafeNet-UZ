import httpx
import pytest

from analyzer.external_apis import ExternalAPIService

VT_URL = "https://www.virustotal.com/api/v3/urls/"
UH_URL = "https://urlhaus-api.abuse.ch/v1/url/"
GSB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

TEST_URL = "https://example.com/login"


def make_client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def json_handler(body: dict, status: int = 200):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=body, request=request)

    return handler


def boom_handler(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("connection reset", request=request)


async def test_all_skipped_without_keys():
    def unexpected(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"hech qanday so'rov ketmasligi kerak: {request.url}")

    service = ExternalAPIService(client=make_client(unexpected))
    assert await service.check_virustotal_url(TEST_URL) == {
        "status": "skipped",
        "source": "virustotal",
    }
    assert await service.check_urlhaus(TEST_URL) == {
        "status": "skipped",
        "source": "urlhaus",
    }
    assert await service.check_google_safebrowsing(TEST_URL) == {
        "status": "skipped",
        "source": "google_safebrowsing",
    }


async def test_virustotal_stats_parsed():
    body = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 5,
                    "suspicious": 2,
                    "harmless": 90,
                }
            }
        }
    }
    service = ExternalAPIService(
        virustotal_api_key="vt-key", client=make_client(json_handler(body))
    )
    result = await service.check_virustotal_url(TEST_URL)
    assert result == {
        "status": "done",
        "source": "virustotal",
        "malicious": 5,
        "suspicious": 2,
        "harmless": 90,
    }


async def test_virustotal_not_seen_returns_zeros():
    service = ExternalAPIService(
        virustotal_api_key="vt-key",
        client=make_client(json_handler({"error": {"code": "NotFoundError"}}, 404)),
    )
    result = await service.check_virustotal_url(TEST_URL)
    assert result["status"] == "done"
    assert result["malicious"] == 0
    assert result["suspicious"] == 0
    assert result["harmless"] == 0
    assert result["note"] == "not_seen"


async def test_virustotal_http_error():
    service = ExternalAPIService(
        virustotal_api_key="vt-key",
        client=make_client(json_handler({"error": "quota"}, 429)),
    )
    result = await service.check_virustotal_url(TEST_URL)
    assert result == {"status": "error", "source": "virustotal", "reason": "http"}


async def test_virustotal_network_error():
    service = ExternalAPIService(
        virustotal_api_key="vt-key", client=make_client(boom_handler)
    )
    result = await service.check_virustotal_url(TEST_URL)
    assert result == {"status": "error", "source": "virustotal", "reason": "network"}


async def test_virustotal_invalid_json():
    def html_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>not json</html>", request=request)

    service = ExternalAPIService(
        virustotal_api_key="vt-key", client=make_client(html_handler)
    )
    result = await service.check_virustotal_url(TEST_URL)
    assert result == {"status": "error", "source": "virustotal", "reason": "parse"}


async def test_urlhaus_found_with_blacklist_count():
    body = {
        "query_status": "ok",
        "id": "105821",
        "threat": "malware_download",
        "url_status": "active",
        "blacklists": {"spamhaus_dbl": "listed", "surbl": "not listed"},
        "urlhaus_reference": "https://urlhaus.abuse.ch/url/105821/",
    }
    service = ExternalAPIService(
        urlhaus_api_key="uh-key", client=make_client(json_handler(body))
    )
    result = await service.check_urlhaus(TEST_URL)
    assert result["status"] == "done"
    assert result["found"] is True
    assert result["threat"] == "malware_download"
    assert result["blacklist_count"] == 1
    assert result["reference"] == "https://urlhaus.abuse.ch/url/105821/"


async def test_urlhaus_not_found():
    service = ExternalAPIService(
        urlhaus_api_key="uh-key",
        client=make_client(json_handler({"query_status": "no_results"})),
    )
    result = await service.check_urlhaus(TEST_URL)
    assert result == {"status": "done", "source": "urlhaus", "found": False}


async def test_urlhaus_http_error():
    service = ExternalAPIService(
        urlhaus_api_key="uh-key",
        client=make_client(json_handler({"query_status": "invalid_url"}, 400)),
    )
    result = await service.check_urlhaus(TEST_URL)
    assert result == {"status": "error", "source": "urlhaus", "reason": "http"}


async def test_urlhaus_network_error():
    service = ExternalAPIService(
        urlhaus_api_key="uh-key", client=make_client(boom_handler)
    )
    result = await service.check_urlhaus(TEST_URL)
    assert result == {"status": "error", "source": "urlhaus", "reason": "network"}


async def test_urlhaus_blacklists_int_branch():
    body = {"query_status": "ok", "threat": "malware_download", "blacklists": 3}
    service = ExternalAPIService(
        urlhaus_api_key="uh-key", client=make_client(json_handler(body))
    )
    result = await service.check_urlhaus(TEST_URL)
    assert result["blacklist_count"] == 3


async def test_google_safebrowsing_flagged():
    body = {"matches": [{"threatType": "MALWARE"}, {"threatType": "SOCIAL_ENGINEERING"}]}
    service = ExternalAPIService(
        google_safebrowsing_api_key="gsb-key", client=make_client(json_handler(body))
    )
    result = await service.check_google_safebrowsing(TEST_URL)
    assert result["status"] == "done"
    assert result["flagged"] is True
    assert result["threats"] == ["MALWARE", "SOCIAL_ENGINEERING"]


async def test_google_safebrowsing_clean():
    service = ExternalAPIService(
        google_safebrowsing_api_key="gsb-key",
        client=make_client(json_handler({"matches": []})),
    )
    result = await service.check_google_safebrowsing(TEST_URL)
    assert result["status"] == "done"
    assert result["flagged"] is False
    assert result["threats"] == []


async def test_google_safebrowsing_http_error():
    service = ExternalAPIService(
        google_safebrowsing_api_key="gsb-key",
        client=make_client(json_handler({"error": "API key invalid"}, 400)),
    )
    result = await service.check_google_safebrowsing(TEST_URL)
    assert result == {
        "status": "error",
        "source": "google_safebrowsing",
        "reason": "http",
    }


async def test_google_safebrowsing_network_error():
    service = ExternalAPIService(
        google_safebrowsing_api_key="gsb-key", client=make_client(boom_handler)
    )
    result = await service.check_google_safebrowsing(TEST_URL)
    assert result == {
        "status": "error",
        "source": "google_safebrowsing",
        "reason": "network",
    }


async def test_google_safebrowsing_invalid_json():
    def text_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="internal error", request=request)

    service = ExternalAPIService(
        google_safebrowsing_api_key="gsb-key", client=make_client(text_handler)
    )
    result = await service.check_google_safebrowsing(TEST_URL)
    assert result == {
        "status": "error",
        "source": "google_safebrowsing",
        "reason": "http",
    }


async def test_payload_carries_url_to_all_services():
    seen: list[str] = []

    def recording_handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json={}, request=request)

    service = ExternalAPIService(
        virustotal_api_key="vt-key",
        urlhaus_api_key="uh-key",
        google_safebrowsing_api_key="gsb-key",
        client=make_client(recording_handler),
    )
    await service.check_virustotal_url(TEST_URL)
    await service.check_urlhaus(TEST_URL)
    await service.check_google_safebrowsing(TEST_URL)
    assert len(seen) == 3
    assert any(VT_URL in url and "vt-key" not in url for url in seen)
    assert any(UH_URL in url for url in seen)
    assert any(GSB_URL in url and "key=" in url for url in seen)