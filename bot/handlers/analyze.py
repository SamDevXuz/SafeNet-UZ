import logging

from aiogram import Router
from aiogram.types import Message

from analyzer.analysis import (
    VERDICT_DANGEROUS,
    VERDICT_SUSPICIOUS,
    analyze_url as analyze_safety,
    verdict_code,
)
from analyzer.url_parser import URL_RE as _URL_RE
from analyzer.url_parser import parse_url
from core.config import get_settings

router = Router(name="analyze")


def _build_verdict(vt: dict, urlhaus: dict, gsb: dict) -> str:
    code = verdict_code(vt, urlhaus, gsb)
    if code == VERDICT_DANGEROUS:
        return "🔴 *XAVFLI* — bu havolani ochmang va hech kimga yubormang!"
    if code == VERDICT_SUSPICIOUS:
        return "🟡 *SHUBHALI* — ehtiyotkorlik bilan munosabatda bo'ling."
    return "🟢 *XAVFSIZ* — tahlil natijasiga ko'ra xavf aniqlanmadi."


def _line_for(value: dict, label: str, done_text: str) -> str:
    status = value.get("status")
    if status == "skipped":
        return f"{label}: ⏭️ *O'tkazib yuborildi* (API kaliti kiritilmagan)"
    if status == "error":
        return f"{label}: ❌ *Tekshirilmadi* (texnik xatolik)"
    return f"{label}: {done_text}"


def format_report(url: str, hostname: str, vt: dict, urlhaus: dict, gsb: dict) -> str:
    vt_line = _line_for(
        vt,
        "VirusTotal",
        f"✖️ *Malicious:* `{vt.get('malicious', 0)}`  "
        f"⚠️ *Suspicious:* `{vt.get('suspicious', 0)}`  "
        f"✅ *Harmless:* `{vt.get('harmless', 0)}`",
    )

    if urlhaus.get("status") == "done":
        if urlhaus.get("found"):
            uh_text = (
                f"✔️ *Qora ro'yxatda:* `{urlhaus.get('threat')}`  "
                f"📌 Blacklistlar: `{urlhaus.get('blacklist_count')}`"
            )
        else:
            uh_text = "🟢 Qora ro'yxatda *topilmadi*"
    else:
        uh_text = ""
    uh_line = _line_for(urlhaus, "URLhaus", uh_text)

    if gsb.get("status") == "done":
        gsb_text = (
            "🔴 `" + "`, `".join(gsb.get("threats")) + "` aniqlandi"
            if gsb.get("flagged")
            else "🟢 Xavf *aniqlanmadi*"
        )
    else:
        gsb_text = ""
    gsb_line = _line_for(gsb, "Google Safe Browsing", gsb_text)

    return (
        "🛡️ *SafeNet UZ — URL tahlili*\n\n"
        f"🔗 *Havola:* `{url}`\n"
        f"🌐 *Domayn:* `{hostname}`\n\n"
        "━━━━━━━━━━━━━━━━\n"
        f"✅ {vt_line}\n"
        f"✅ {uh_line}\n"
        f"✅ {gsb_line}\n"
        "━━━━━━━━━━━━━━━━\n\n"
        f"*Xulosa:* {_build_verdict(vt, urlhaus, gsb)}"
    )


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
    settings = get_settings()

    progress = await message.answer("⏳ *Tahlil boshlandi...*", parse_mode="Markdown")

    try:
        result = await analyze_safety(raw_url, settings)
    except Exception:
        await progress.edit_text(
            "❌ *Tahlil paytida kutilmagan xatolik yuz berdi.*\n"
            "Iltimos, keyinroq qayta urinib ko'ring.",
            parse_mode="Markdown",
        )
        return

    await progress.edit_text(
        format_report(
            raw_url,
            parsed.hostname,
            result.virustotal,
            result.urlhaus,
            result.google_safebrowsing,
        ),
        parse_mode="Markdown",
    )

    await _record_analysis(raw_url, parsed.hostname, result, message)


async def _record_analysis(
    url: str, hostname: str, result: object, message: Message
) -> None:
    try:
        from core.database import get_database

        author = getattr(message, "from_user", None)
        username = getattr(author, "username", None) if author else None
        await get_database().record_analysis(
            url=url,
            hostname=hostname,
            verdict=str(result.verdict),
            source_bot_username=username,
        )
    except Exception:
        logging.getLogger(__name__).warning(
            "Analiz natijasi bazaga yozilmadi: %s", url, exc_info=True
        )