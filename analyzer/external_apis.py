import base64
import logging

import httpx

logger = logging.getLogger(__name__)

VIRUSTOTAL_LOOKUP_URL = "https://www.virustotal.com/api/v3/urls/{url_id}"
URLHAUS_REPORT_URL = "https://urlhaus-api.abuse.ch/v1/url/"
GOOGLE_SAFEBROWSING_FIND_URL = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)

GOOGLE_THREAT_TYPES = ("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE")


class ExternalAPIService:
    def __init__(
        self,
        virustotal_api_key: str | None = None,
        urlhaus_api_key: str | None = None,
        google_safebrowsing_api_key: str | None = None,
        timeout: float = 10.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.virustotal_api_key = virustotal_api_key
        self.urlhaus_api_key = urlhaus_api_key
        self.google_safebrowsing_api_key = google_safebrowsing_api_key
        self._client = client or httpx.AsyncClient(
            timeout=timeout, follow_redirects=False
        )
        self._owns_client = client is None

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> "ExternalAPIService":
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()

    async def check_virustotal_url(self, url: str) -> dict:
        if not self.virustotal_api_key:
            return {"status": "skipped", "source": "virustotal"}
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": self.virustotal_api_key, "Accept": "application/json"}
        try:
            response = await self._client.get(
                VIRUSTOTAL_LOOKUP_URL.format(url_id=url_id), headers=headers
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return {
                    "status": "done",
                    "source": "virustotal",
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 0,
                    "note": "not_seen",
                }
            logger.warning("VirusTotal HTTP %s: %s", exc.response.status_code, exc)
            return {"status": "error", "source": "virustotal", "reason": "http"}
        except httpx.RequestError as exc:
            logger.warning("VirusTotal network error: %s", exc)
            return {"status": "error", "source": "virustotal", "reason": "network"}
        try:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        except (KeyError, ValueError) as exc:
            logger.warning("VirusTotal parse error: %s", exc)
            return {"status": "error", "source": "virustotal", "reason": "parse"}
        return {
            "status": "done",
            "source": "virustotal",
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "harmless": int(stats.get("harmless", 0)),
        }

    async def check_urlhaus(self, url: str) -> dict:
        if not self.urlhaus_api_key:
            return {"status": "skipped", "source": "urlhaus"}
        headers = {"Auth-Key": self.urlhaus_api_key}
        try:
            response = await self._client.post(
                URLHAUS_REPORT_URL, data={"url": url}, headers=headers
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            logger.warning("URLhaus HTTP %s: %s", exc.response.status_code, exc)
            return {"status": "error", "source": "urlhaus", "reason": "http"}
        except httpx.RequestError as exc:
            logger.warning("URLhaus network error: %s", exc)
            return {"status": "error", "source": "urlhaus", "reason": "network"}
        try:
            data = response.json()
        except ValueError as exc:
            logger.warning("URLhaus parse error: %s", exc)
            return {"status": "error", "source": "urlhaus", "reason": "parse"}
        if data.get("query_status") != "ok":
            return {"status": "done", "source": "urlhaus", "found": False}
        blacklists_raw = data.get("blacklists") or {}
        if isinstance(blacklists_raw, dict):
            blacklist_count = sum(
                1 for value in blacklists_raw.values() if value == "listed"
            )
        else:
            blacklist_count = int(blacklists_raw) if blacklists_raw else 0
        return {
            "status": "done",
            "source": "urlhaus",
            "found": True,
            "threat": data.get("threat"),
            "blacklist_count": blacklist_count,
            "reference": data.get("urlhaus_reference"),
        }

    async def check_google_safebrowsing(self, url: str) -> dict:
        if not self.google_safebrowsing_api_key:
            return {"status": "skipped", "source": "google_safebrowsing"}
        payload = {
            "client": {"clientId": "safenetuz", "clientVersion": "0.1.0"},
            "threatInfo": {
                "threatTypes": list(GOOGLE_THREAT_TYPES),
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        params = {"key": self.google_safebrowsing_api_key}
        try:
            response = await self._client.post(
                GOOGLE_SAFEBROWSING_FIND_URL, params=params, json=payload
            )
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPStatusError as exc:
            logger.warning("Google Safe Browsing HTTP %s: %s", exc.response.status_code, exc)
            return {"status": "error", "source": "google_safebrowsing", "reason": "http"}
        except httpx.RequestError as exc:
            logger.warning("Google Safe Browsing network error: %s", exc)
            return {"status": "error", "source": "google_safebrowsing", "reason": "network"}
        except ValueError as exc:
            logger.warning("Google Safe Browsing parse error: %s", exc)
            return {"status": "error", "source": "google_safebrowsing", "reason": "parse"}
        matches = [item.get("threatType") for item in data.get("matches", [])]
        return {
            "status": "done",
            "source": "google_safebrowsing",
            "flagged": bool(matches),
            "threats": matches,
        }