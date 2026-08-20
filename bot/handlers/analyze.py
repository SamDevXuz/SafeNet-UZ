import logging
import re

from aiogram import F, Router
from aiogram.types import Message

from analyzer.analysis import (
    VERDICT_DANGEROUS,
    VERDICT_SUSPICIOUS,
    verdict_code,
)
from analyzer.pipeline import SOURCE_USER_REPORT, check_url as pipeline_check_url
from analyzer.url_parser import URL_RE as _URL_RE
from analyzer.url_parser import parse_url
from core.config import get_settings

router = Router(name="analyze")

_APK_RE = re.compile(r"\.apk\b", re.IGNORECASE)


def _build_verdict(vt: dict, urlhaus: dict, gsb: dict, heuristic: dict | None = None) -> str:
    code = verdict_code(vt, urlhaus, gsb, heuristic)
    if code == VERDICT_DANGEROUS:
        return "🔴 *XAVFLI* — bu havolani ochmang va hech kimga yubormang!"
    if code == VERDICT_SUSPICIOUS:
        return "🟡 *SHUBHALI* — ehtiyotkorlik bilan munosabatda bo'ling."
    return "🟢 *XAVFSIZ* — tahlil natijasiga ko'ra xavf aniqlanmadi."


def _heuristic_line(heuristic: dict | None) -> str:
    if not heuristic or heuristic.get("level") in (None, "none"):
        return ""
    level_text = "🔴 *Kritik*" if heuristic.get("level") == "dangerous" else "🟡 *Shubhali*"
    flags = heuristic.get("flags") or []
    flags_text = ", ".join(str(flag) for flag in flags[:6]) or "xususiyatlar aniqlandi"
    return f"{level_text} lokal tahlil: `{flags_text}`"


def _line_for(value: dict, label: str, done_text: str) -> str:
    status = value.get("status")
    if status == "skipped":
        return f"{label}: ⏭️ *O'tkazib yuborildi* (API kaliti kiritilmagan)"
    if status == "error":
        return f"{label}: ❌ *Tekshirilmadi* (texnik xatolik)"
    return f"{label}: {done_text}"


def format_report(
    url: str,
    hostname: str,
    vt: dict,
    urlhaus: dict,
    gsb: dict,
    heuristic: dict | None = None,
) -> str:
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

    heuristic_line = _heuristic_line(heuristic)
    heuristic_block = f"\n✅ {heuristic_line}\n" if heuristic_line else ""

    return (
        "🛡️ *SafeNet UZ — URL tahlili*\n\n"
        f"🔗 *Havola:* `{url}`\n"
        f"🌐 *Domayn:* `{hostname}`\n\n"
        "━━━━━━━━━━━━━━━━\n"
        f"✅ {vt_line}\n"
        f"✅ {uh_line}\n"
        f"✅ {gsb_line}\n"
        f"{heuristic_block}"
        "━━━━━━━━━━━━━━━━\n\n"
        f"*Xulosa:* {_build_verdict(vt, urlhaus, gsb, heuristic)}"
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
        cache, database = _get_analysis_backend()
        result = await pipeline_check_url(
            raw_url,
            cache=cache,
            database=database,
            settings=settings,
            source=SOURCE_USER_REPORT,
        )
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
            result.heuristic,
        ),
        parse_mode="Markdown",
    )

    await _record_analysis(raw_url, parsed.hostname, result, message)


@router.message(F.document)
async def handle_document(message: Message) -> None:
    document = message.document
    file_name = (document.file_name or "").lower() if document else ""
    if not _APK_RE.search(file_name):
        return

    if message.chat.type in {"group", "supergroup"}:
        return

    await message.answer(
        "⛔ *APK fayl qabul qilinmadi.*\n\n"
        "Xavfsizlik uchun bot `.apk` fayllarni qabul qilmaydi. "
        "Faylni faqat rasmiy manbalardan o'rnating.",
        parse_mode="Markdown",
    )


def _get_analysis_backend() -> tuple:
    cache = None
    database = None
    try:
        from database.cache import get_cache

        cache = get_cache()
    except RuntimeError:
        pass
    try:
        from database.session import get_database

        database = get_database()
    except RuntimeError:
        pass
    return cache, database


async def _record_analysis(
    url: str, hostname: str, result: object, message: Message
) -> None:
    try:
        from database.session import get_database

        database = get_database()
        author = getattr(message, "from_user", None)
        username = getattr(author, "username", None) if author else None
        await database.record_analysis(
            url=url,
            hostname=hostname,
            verdict=str(result.verdict),
            source_bot_username=username,
        )
    except Exception:
        logging.getLogger(__name__).warning(
            "Analiz natijasi bazaga yozilmadi: %s", url, exc_info=True
        )