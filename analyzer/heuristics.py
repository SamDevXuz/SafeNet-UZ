import asyncio
import logging
import re

import httpx

logger = logging.getLogger(__name__)

IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "club", "online", "site",
    "icu", "rest", "click", "link", "cam", "info", "pro", "work",
}

SUSPICIOUS_KEYWORDS = (
    "account", "verify", "wallet", "login", "secure", "camera", "webcam",
    "mic", "permission", "unlock", "confirm", "suspend", "deactivate",
    "security", "prize", "bonus", "lottery", "crypto", "whatsapp",
    "telegram", "instagram", "facebook", "google", "apple", "netflix",
    "steal", "fraud", "access",
)

JS_CAPTURE_SIGNALS = (
    "getusermedia",
    "mediadevices",
    "navigator.mediadevices",
    "user-mediadevices",
)

PAGE_KEYWORDS = (
    "verify you are human",
    "confirm your identity",
    "allow camera",
    "camera access",
    "microphone access",
    "video capture",
    "face id",
    "scan your face",
    "photo access",
    "take a photo",
)

MAX_PROBE_BYTES = 32768
PROBE_TIMEOUT_SECONDS = 8


def hostname_flags(hostname: str) -> tuple[str, ...]:
    flags: list[str] = []
    host = (hostname or "").lower().rstrip(".")
    if not host:
        return tuple(flags)
    if IP_RE.match(host):
        flags.append("ip_literal_host")
    if "xn--" in host:
        flags.append("punycode")
    labels = host.split(".")
    if len(labels) >= 2 and labels[-1] in SUSPICIOUS_TLDS:
        flags.append(f"suspicious_tld:{labels[-1]}")
    return tuple(flags)


def path_flags(url: str, hostname: str, port: int | None) -> tuple[str, ...]:
    flags: list[str] = []
    if port is not None and port not in (80, 443):
        flags.append(f"nonstandard_port:{port}")
    fragment = ""
    try:
        scheme_end = url.find("://")
        rest = url[scheme_end + 3 :] if scheme_end != -1 else url
        slash = rest.find("/")
        if slash != -1:
            fragment = rest[slash:].lower()
    except Exception:
        fragment = ""
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in fragment:
            flags.append(f"keyword:{keyword}")
    return tuple(dict.fromkeys(flags))


async def _probe_page(url: str, timeout: float) -> str | None:
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
        )
    }
    try:
        async with asyncio.timeout(PROBE_TIMEOUT_SECONDS):
            async with httpx.AsyncClient(
                follow_redirects=True, timeout=timeout, headers=headers, verify=False
            ) as client:
                response = await client.get(url)
                content = await response.aread()
                if response.status_code >= 400:
                    return None
                return content[:MAX_PROBE_BYTES].decode("utf-8", errors="ignore").lower()
    except Exception:
        return None


def page_flags(sample: str | None) -> tuple[str, ...]:
    if not sample:
        return ()
    flags: list[str] = []
    for signal in JS_CAPTURE_SIGNALS:
        if signal in sample:
            flags.append(f"js_capture:{signal}")
    for keyword in PAGE_KEYWORDS:
        if keyword in sample:
            flags.append(f"page:{keyword}")
    return tuple(flags)


def _level_for(all_flags: tuple[str, ...]) -> tuple[int, str]:
    js_capture = any(f.startswith("js_capture:") for f in all_flags)
    if js_capture:
        return 3, "dangerous"
    if len(all_flags) > 0:
        return 2, "suspicious"
    return 0, "none"


def scan_sync(url: str, hostname: str, port: int | None) -> tuple[tuple[str, ...], int, str]:
    all_flags: list[str] = []
    all_flags.extend(hostname_flags(hostname))
    all_flags.extend(path_flags(url, hostname, port))
    all_flags = list(dict.fromkeys(all_flags))
    if not all_flags:
        return (), 0, "none"
    if any(f.startswith("js_capture:") for f in all_flags):
        return tuple(all_flags), 3, "dangerous"
    return tuple(all_flags), 2, "suspicious"


async def scan_url(
    url: str,
    hostname: str,
    port: int | None,
    *,
    page_probe: bool = True,
    timeout: float = 10.0,
) -> tuple[tuple[str, ...], int, str]:
    flags, score, level = scan_sync(url, hostname, port)
    if not page_probe or level == "dangerous":
        return flags, score, level
    sample = await _probe_page(url, timeout)
    sample_page_flags = page_flags(sample)
    if sample_page_flags:
        all_flags = tuple(dict.fromkeys(flags + sample_page_flags))
        return all_flags, *_level_for(all_flags)
    return flags, score, level