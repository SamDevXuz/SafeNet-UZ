import asyncio
from dataclasses import dataclass, field

from analyzer.external_apis import ExternalAPIService
from analyzer.heuristics import scan_url
from analyzer.url_parser import parse_url

VERDICT_SAFE = "XAVFSIZ"
VERDICT_SUSPICIOUS = "SHUBHALI"
VERDICT_DANGEROUS = "XAVFLI"


@dataclass(frozen=True)
class AnalysisResult:
    url: str
    virustotal: dict
    urlhaus: dict
    google_safebrowsing: dict
    heuristic: dict = field(default_factory=dict)

    @property
    def verdict(self) -> str:
        return verdict_code(
            self.virustotal, self.urlhaus, self.google_safebrowsing, self.heuristic
        )

    @property
    def is_dangerous(self) -> bool:
        return self.verdict == VERDICT_DANGEROUS


def verdict_code(vt: dict, urlhaus: dict, gsb: dict, heuristic: dict | None = None) -> str:
    vt_done = vt.get("status") == "done"
    if (
        (vt_done and vt.get("malicious", 0) > 0)
        or (urlhaus.get("status") == "done" and urlhaus.get("found"))
        or (gsb.get("status") == "done" and gsb.get("flagged"))
    ):
        return VERDICT_DANGEROUS
    heuristic = heuristic or {}
    if heuristic.get("level") == "dangerous":
        return VERDICT_DANGEROUS
    if vt_done and vt.get("suspicious", 0) > 0:
        return VERDICT_SUSPICIOUS
    if heuristic.get("level") == "suspicious":
        return VERDICT_SUSPICIOUS
    return VERDICT_SAFE


async def analyze_url(url: str, settings) -> AnalysisResult:
    parsed = parse_url(url)
    async with ExternalAPIService(
        virustotal_api_key=settings.virustotal_api_key,
        urlhaus_api_key=settings.urlhaus_api_key,
        google_safebrowsing_api_key=settings.google_safebrowsing_api_key,
        timeout=settings.request_timeout,
    ) as service:
        checks = [
            service.check_virustotal_url(url),
            service.check_urlhaus(url),
            service.check_google_safebrowsing(url),
        ]
        if getattr(settings, "heuristics_enabled", True):
            checks.append(
                scan_url(
                    url,
                    parsed.hostname,
                    parsed.port,
                    page_probe=getattr(settings, "page_probe_enabled", True),
                    timeout=settings.request_timeout,
                )
            )
        results = await asyncio.gather(*checks, return_exceptions=True)

    vt, uh, gsb = (results[0], results[1], results[2])
    for idx, result in enumerate((vt, uh, gsb)):
        if isinstance(result, BaseException):
            results[idx] = {"status": "error", "source": "internal", "reason": "network"}
    vt, uh, gsb = results[0], results[1], results[2]

    heuristic: dict = {"level": "none", "flags": []}
    if len(results) > 3 and not isinstance(results[3], BaseException):
        flags, score, level = results[3]
        heuristic = {"level": level, "score": score, "flags": list(flags)}

    return AnalysisResult(
        url=url,
        virustotal=vt,
        urlhaus=uh,
        google_safebrowsing=gsb,
        heuristic=heuristic,
    )