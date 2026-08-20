import re
from dataclasses import dataclass
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)


@dataclass(frozen=True)
class ParsedUrl:
    raw: str
    scheme: str
    hostname: str
    port: int | None
    path: str
    query: str

    @property
    def is_https(self) -> bool:
        return self.scheme.lower() == "https"


def parse_url(raw: str) -> ParsedUrl:
    normalized = raw if "://" in raw else f"https://{raw}"
    parsed = urlparse(normalized)
    return ParsedUrl(
        raw=raw,
        scheme=parsed.scheme.lower(),
        hostname=parsed.hostname or "",
        port=parsed.port,
        path=parsed.path,
        query=parsed.query,
    )