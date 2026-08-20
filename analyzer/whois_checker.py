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
    return WhoisInfo(
        domain=domain,
        registrar=str(data.registrar) if data.registrar else None,
        creation_date=str(data.creation_date) if data.creation_date else None,
        expiration_date=str(data.expiration_date) if data.expiration_date else None,
        country=str(data.country) if data.country else None,
    )