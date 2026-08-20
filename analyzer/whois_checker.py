import asyncio
from dataclasses import dataclass

import whois


@dataclass(frozen=True)
class WhoisInfo:
    domain: str
    registrar: str | None
    creation_date: str | None
    expiration_date: str | None
    country: str | None


async def check_whois(domain: str) -> WhoisInfo:
    data = await asyncio.to_thread(whois.whois, domain)
    if not data.domain_name:
        raise ValueError(f"WHOIS ma'lumotlari topilmadi: {domain}")
    registrar = getattr(data, "registrar", None)
    creation_date = getattr(data, "creation_date", None)
    expiration_date = getattr(data, "expiration_date", None)
    country = getattr(data, "country", None)
    return WhoisInfo(
        domain=domain,
        registrar=str(registrar) if registrar else None,
        creation_date=str(creation_date) if creation_date else None,
        expiration_date=str(expiration_date) if expiration_date else None,
        country=str(country) if country else None,
    )