import asyncio
from dataclasses import dataclass

from analyzer.external_apis import ExternalAPIService

VERDICT_SAFE = "XAVFSIZ"
VERDICT_SUSPICIOUS = "SHUBHALI"
VERDICT_DANGEROUS = "XAVFLI"


@dataclass(frozen=True)
class AnalysisResult:
    url: str
    virustotal: dict
    urlhaus: dict
    google_safebrowsing: dict

    @property
    def verdict(self) -> str:
        return verdict_code(self.virustotal, self.urlhaus, self.google_safebrowsing)

    @property
    def is_dangerous(self) -> bool:
        return self.verdict == VERDICT_DANGEROUS


def verdict_code(vt: dict, urlhaus: dict, gsb: dict) -> str:
    vt_done = vt.get("status") == "done"
    if (
        (vt_done and vt.get("malicious", 0) > 0)
        or (urlhaus.get("status") == "done" and urlhaus.get("found"))
        or (gsb.get("status") == "done" and gsb.get("flagged"))
    ):
        return VERDICT_DANGEROUS
    if vt_done and vt.get("suspicious", 0) > 0:
        return VERDICT_SUSPICIOUS
    return VERDICT_SAFE


async def analyze_url(url: str, settings) -> AnalysisResult:
    async with ExternalAPIService(
        virustotal_api_key=settings.virustotal_api_key,
        urlhaus_api_key=settings.urlhaus_api_key,
        google_safebrowsing_api_key=settings.google_safebrowsing_api_key,
        timeout=settings.request_timeout,
    ) as service:
        vt, uh, gsb = await asyncio.gather(
            service.check_virustotal_url(url),
            service.check_urlhaus(url),
            service.check_google_safebrowsing(url),
        )
    return AnalysisResult(
        url=url,
        virustotal=vt,
        urlhaus=uh,
        google_safebrowsing=gsb,
    )