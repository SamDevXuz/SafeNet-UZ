import asyncio
import logging
import re

from aiogram import F, Router
from aiogram.exceptions import TelegramAPIError
from aiogram.types import Message

from analyzer.analysis import analyze_url
from analyzer.url_parser import URL_RE
from core.config import get_settings

logger = logging.getLogger(__name__)

router = Router(name="group_guard")

_APK_RE = re.compile(r"\.apk\b", re.IGNORECASE)
_TG_MENTION_RE = re.compile(r"(?:t\.me/|telegram\.me/|@)\w{3,}", re.IGNORECASE)

_background: set[asyncio.Task] = set()


@router.message(F.chat.type.in_({"group", "supergroup"}))
async def guard_group_message(message: Message) -> None:
    threat = _detect_threat(message)
    if threat is not None:
        _spawn(_moderate(message, threat))
    return True


def _detect_threat(message: Message) -> dict | None:
    text = message.text or message.caption or ""
    url_match = URL_RE.search(text)
    has_apk = _has_apk(message)
    if url_match is None and not has_apk and not _TG_MENTION_RE.search(text):
        return None
    return {
        "url": url_match.group(0) if url_match else None,
        "apk": has_apk,
        "mention": bool(_TG_MENTION_RE.search(text)),
    }


def _has_apk(message: Message) -> bool:
    document = getattr(message, "document", None)
    if document is None:
        return False
    return bool(_APK_RE.search(getattr(document, "file_name", "") or ""))


async def _moderate(message: Message, threat: dict) -> None:
    try:
        settings = get_settings()
        if threat["url"] is not None:
            result = await analyze_url(threat["url"], settings)
            dangerous = result.is_dangerous
        else:
            dangerous = threat["apk"] and settings.group_guard_block_apk
        if dangerous:
            await _punish(message, settings)
    except Exception:
        logger.warning(
            "Guruh avtomoderatsiyasi xatosi: %s", message.chat.id, exc_info=True
        )


async def _punish(message: Message, settings) -> None:
    try:
        await message.delete()
    except TelegramAPIError as exc:
        logger.warning("Xabarni o'chirib bo'lmadi: %s", exc)

    sender = getattr(message, "from_user", None)
    if sender is not None:
        name = (
            getattr(sender, "full_name", None)
            or getattr(sender, "username", None)
            or "Foydalanuvchi"
        )
    else:
        name = "Foydalanuvchi"
    name = _escape_md(str(name))

    try:
        warning = await message.answer(
            "⚠️ **DIQQAT: FIRIBGARLIK (PHISHING)!**\n\n"
            f"[{name}] yuborgan havola/fayl xavfli deb topildi "
            "va xavfsizlik yuzasidan o'chirildi.\n\n"
            "*Plastik karta ma'lumotlaringiz va SMS kodlarni hech qachon "
            "shubhali saytlarga kiritmang!*",
            parse_mode="Markdown",
        )
    except TelegramAPIError as exc:
        logger.warning("Ogohlantirish yuborilmadi: %s", exc)
        return

    await asyncio.sleep(settings.group_guard_warning_ttl)
    try:
        await warning.delete()
    except TelegramAPIError:
        pass


def _escape_md(text: str) -> str:
    for char in ("\\", "_", "*", "`", "[", "]"):
        text = text.replace(char, "\\" + char)
    return text


def _spawn(coro) -> None:
    task = asyncio.create_task(coro)
    _background.add(task)
    task.add_done_callback(_background.discard)