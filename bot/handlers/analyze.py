import re

from aiogram import Router
from aiogram.types import Message

from analyzer.url_parser import parse_url

router = Router(name="analyze")

_URL_RE = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)


@router.message()
async def analyze_url(message: Message) -> None:
    text = message.text or message.caption or ""
    match = _URL_RE.search(text)
    if not match:
        await message.answer(
            "Havola topilmadi. Tahlil qilish uchun to'liq URL manzilni yuboring."
        )
        return

    raw_url = match.group(0)
    parsed = parse_url(raw_url)
    await message.answer(
        f"Analiz boshlanmoqda...\n\n"
        f"Havola: {raw_url}\n"
        f"Domayn: {parsed.hostname}\n"
        f"Protokol: {parsed.scheme}\n\n"
        f"DNS va WHOIS tekshiruvi tez orada qo'shiladi."
    )