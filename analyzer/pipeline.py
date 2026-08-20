import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from analyzer.analysis import (
    VERDICT_DANGEROUS,
    VERDICT_SAFE,
    analyze_url as analyze_externally,
)
from analyzer.url_parser import parse_url
from database.models import (
    SOURCE_EXTERNAL_API,
    SOURCE_USER_REPORT,
    STATUS_CLEAN,
    STATUS_MALICIOUS,
    THREAT_BOT,
    THREAT_MALWARE,
    THREAT_PHISHING,
    sha256_hex,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class URLScanResult:
    url: str
    verdict: str
    status: str
    threat_type: str | None
    source: str
    cached: bool
    virustotal: dict
    urlhaus: dict
    google_safebrowsing: dict
    record_id: int | None = None


@dataclass(frozen=True)
class APKScanResult:
    file_hash: str
    file_name: str
    status: str
    malicious_score: int
    cached: bool
    record_id: int | None = None


def _normalized_url(url: str) -> str:
    return url if "://" in url else f"https://{url}"


def _threat_type_from(gsb: dict, urlhaus: dict) -> str | None:
    threats = [
        str(item)
        for item in gsb.get("threats", [])
        if gsb.get("status") == "done" and gsb.get("flagged")
    ]
    if threats:
        if "SOCIAL_ENGINEERING" in threats:
            return THREAT_PHISHING
        return THREAT_MALWARE
    if urlhaus.get("status") == "done" and urlhaus.get("found"):
        threat = str(urlhaus.get("threat") or "").lower()
        if "c2" in threat or "bot" in threat:
            return THREAT_BOT
        if "phish" in threat:
            return THREAT_PHISHING
        return THREAT_MALWARE
    return None


def status_from_verdict(verdict: str) -> str:
    return STATUS_MALICIOUS if verdict == VERDICT_DANGEROUS else STATUS_CLEAN


def _payload_for(
    url: str, result, status: str, threat_type: str | None, source: str
) -> dict:
    return {
        "url": url,
        "verdict": result.verdict,
        "status": status,
        "threat_type": threat_type,
        "source": source,
        "ts": datetime.now(timezone.utc).isoformat(),
        "virustotal": result.virustotal,
        "urlhaus": result.urlhaus,
        "google_safebrowsing": result.google_safebrowsing,
    }


def _result_from_payload(payload: dict, url: str) -> URLScanResult:
    return URLScanResult(
        url=url,
        verdict=str(payload.get("verdict", VERDICT_SAFE)),
        status=str(payload.get("status", STATUS_CLEAN)),
        threat_type=payload.get("threat_type"),
        source=str(payload.get("source", SOURCE_USER_REPORT)),
        cached=True,
        virustotal=payload.get("virustotal") or {},
        urlhaus=payload.get("urlhaus") or {},
        google_safebrowsing=payload.get("google_safebrowsing") or {},
    )


async def check_url(
    url: str,
    *,
    cache=None,
    database=None,
    settings=None,
    source: str = SOURCE_USER_REPORT,
    external_analyzer=None,
) -> URLScanResult:
    parsed = parse_url(url)
    normalized = _normalized_url(url)
    url_hash = sha256_hex(normalized)

    payload: dict | None = None
    if cache is not None:
        payload = await cache.get_url(url_hash)
    if payload is None and database is not None:
        try:
            record = await database.get_threat_url(url_hash)
        except Exception:
            logger.warning("Bazadan URL o'qilmadi: %s", normalized, exc_info=True)
            record = None
        if record is not None:
            result = URLScanResult(
                url=normalized,
                verdict=(
                    VERDICT_DANGEROUS
                    if record.status == STATUS_MALICIOUS
                    else VERDICT_SAFE
                ),
                status=record.status,
                threat_type=record.threat_type,
                source=record.source,
                cached=True,
                virustotal={},
                urlhaus={},
                google_safebrowsing={},
                record_id=record.id,
            )
            if cache is not None:
                await cache.set_url(
                    url_hash,
                    _payload_for(
                        normalized,
                        result,
                        result.status,
                        result.threat_type,
                        result.source,
                    ),
                    result.status,
                )
            return result
    if payload is not None:
        cached_result = _result_from_payload(payload, normalized)
        if database is not None:
            try:
                record = await database.save_threat_url(
                    url=normalized,
                    domain=parsed.hostname,
                    status=cached_result.status,
                    threat_type=cached_result.threat_type,
                    source=cached_result.source,
                )
                cached_result = URLScanResult(
                    url=cached_result.url,
                    verdict=cached_result.verdict,
                    status=cached_result.status,
                    threat_type=cached_result.threat_type,
                    source=cached_result.source,
                    cached=True,
                    virustotal=cached_result.virustotal,
                    urlhaus=cached_result.urlhaus,
                    google_safebrowsing=cached_result.google_safebrowsing,
                    record_id=record.id,
                )
            except Exception:
                logger.warning(
                    "Kesh natijasi bazaga yozilmadi: %s", normalized, exc_info=True
                )
        return cached_result

    analyzer = external_analyzer or analyze_externally
    result = await analyzer(normalized, settings)

    status = status_from_verdict(result.verdict)
    threat_type = _threat_type_from(result.google_safebrowsing, result.urlhaus)
    record_id = None
    if database is not None:
        try:
            record = await database.save_threat_url(
                url=normalized,
                domain=parsed.hostname,
                status=status,
                threat_type=threat_type,
                source=source,
            )
            record_id = record.id
        except Exception:
            logger.warning("Tahlil natijasi bazaga yozilmadi: %s", normalized, exc_info=True)
    if cache is not None:
        await cache.set_url(
            url_hash,
            _payload_for(normalized, result, status, threat_type, source),
            status,
        )

    return URLScanResult(
        url=normalized,
        verdict=result.verdict,
        status=status,
        threat_type=threat_type,
        source=source,
        cached=False,
        virustotal=result.virustotal,
        urlhaus=result.urlhaus,
        google_safebrowsing=result.google_safebrowsing,
        record_id=record_id,
    )


async def check_apk(
    file_bytes: bytes,
    file_name: str,
    *,
    cache=None,
    database=None,
    source: str = SOURCE_USER_REPORT,
    package_name: str | None = None,
    malicious_score: int = 0,
) -> APKScanResult:
    file_hash = sha256_hex(file_bytes)
    status = STATUS_MALICIOUS if malicious_score > 0 else STATUS_CLEAN

    if cache is not None:
        payload = await cache.get_apk(file_hash)
        if payload is not None:
            return APKScanResult(
                file_hash=file_hash,
                file_name=str(payload.get("file_name", file_name)),
                status=str(payload.get("status", status)),
                malicious_score=int(payload.get("malicious_score", malicious_score)),
                cached=True,
                record_id=payload.get("record_id"),
            )
    if database is not None:
        try:
            record = await database.get_threat_apk(file_hash)
        except Exception:
            logger.warning("Bazadan APK o'qilmadi: %s", file_name, exc_info=True)
            record = None
        if record is not None:
            if cache is not None:
                await cache.set_apk(
                    file_hash,
                    {
                        "file_name": record.file_name,
                        "status": record.status,
                        "malicious_score": record.malicious_score,
                    },
                    record.status,
                )
            return APKScanResult(
                file_hash=file_hash,
                file_name=record.file_name,
                status=record.status,
                malicious_score=record.malicious_score,
                cached=True,
                record_id=record.id,
            )

    record_id = None
    if database is not None:
        try:
            record = await database.save_threat_apk(
                file_hash=file_hash,
                file_name=file_name,
                package_name=package_name,
                status=status,
                malicious_score=malicious_score,
            )
            record_id = record.id
        except Exception:
            logger.warning("APK natijasi bazaga yozilmadi: %s", file_name, exc_info=True)
    if cache is not None:
        await cache.set_apk(
            file_hash,
            {
                "file_name": file_name,
                "status": status,
                "malicious_score": malicious_score,
            },
            status,
        )

    return APKScanResult(
        file_hash=file_hash,
        file_name=file_name,
        status=status,
        malicious_score=malicious_score,
        cached=False,
        record_id=record_id,
    )