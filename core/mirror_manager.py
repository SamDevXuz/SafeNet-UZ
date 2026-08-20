import asyncio
import logging
import tempfile
from pathlib import Path
from typing import Iterable

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramAPIError
from aiogram.types import BotCommand, FSInputFile

from database.models import hash_token
from database.session import get_database

logger = logging.getLogger(__name__)

ASSETS_DIR = Path(__file__).resolve().parent.parent / "assets"
LOGO_GLOBS = ("logo.png", "logo.jpg", "logo.jpeg")

LOGO_SIZE = 640

BOT_DESCRIPTION = (
    "SafeNet UZ tarmog'idagi phishing va zararli havolalarni aniqlash boti. "
    "Shubhali URL yuboring — VirusTotal, URLhaus va Google Safe Browsing orqali "
    "tekshirib, natijani qaytaramiz."
)
BOT_SHORT_DESCRIPTION = (
    "🛡️ SafeNet UZ — phishing havolalarni tekshiruvchi hamkor bot. Kanal va "
    "guruhlarda ham ishlaydi."
)

TOKEN_PATTERN = r"^\d{5,12}:[A-Za-z0-9_-]{30,40}$"


class MirrorSetupError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class MirrorManager:
    def __init__(self, routers: Iterable = (), webhook_domain: str | None = None) -> None:
        self._routers = list(routers)
        self._webhook_domain = (webhook_domain or "").rstrip("/")
        self._bots: dict[str, Bot] = {}
        self._dispatchers: dict[str, Dispatcher] = {}
        self._tasks: list[asyncio.Task] = []

    @property
    def webhook_mode(self) -> bool:
        return bool(self._webhook_domain)

    @property
    def bot_count(self) -> int:
        return len(self._bots)

    def is_registered(self, bot_token: str) -> bool:
        return any(hash_token(token) == hash_token(bot_token) for token in self._bots)

    async def validate_and_setup_bot(self, bot_token: str) -> dict:
        if self.is_registered(bot_token):
            raise MirrorSetupError("Bu bot allaqachon tarmoqqa ulangan.")

        bot = Bot(
            token=bot_token,
            default=DefaultBotProperties(parse_mode=ParseMode.HTML),
        )

        try:
            me = await bot.get_me()
        except TelegramAPIError as exc:
            await bot.session.close()
            raise MirrorSetupError(
                "Token yaroqsiz. Iltimos, @BotFather'dan yangi tokenni olib qayta yuboring."
            ) from exc

        try:
            await bot.set_my_commands(
                commands=[
                    BotCommand(command="start", description="Boshlash"),
                    BotCommand(command="addbot", description="Bot qo'shish"),
                ]
            )
            await bot.set_my_description(description=BOT_DESCRIPTION)
            await bot.set_my_short_description(short_description=BOT_SHORT_DESCRIPTION)
            await self._set_logo(bot)
        except TelegramAPIError as exc:
            await bot.session.close()
            raise MirrorSetupError(
                "Bot profili sozlashda xatolik yuz berdi. Iltimos, qayta urinib ko'ring."
            ) from exc

        if self.webhook_mode:
            try:
                await bot.set_webhook(
                    url=f"{self._webhook_domain}/webhook/mirror/{bot_token}"
                )
            except TelegramAPIError as exc:
                await bot.session.close()
                raise MirrorSetupError("Webhook o'rnatishda xatolik yuz berdi.") from exc
            mode = "webhook"
            dp = self._build_dispatcher()
            self._dispatchers[bot_token] = dp
        else:
            await self._start_polling(bot)
            mode = "polling"

        self._bots[bot_token] = bot
        await get_database().record_bot(
            bot_token=bot_token,
            username=me.username,
            first_name=me.first_name,
            mode=mode,
        )
        logger.info("Mirror bot ulandi: @%s (%s, %s)", me.username, me.first_name, mode)
        return {
            "status": "done",
            "username": me.username,
            "first_name": me.first_name,
            "mode": mode,
        }

    async def register_tokens_from_env(self, tokens: Iterable[str]) -> None:
        for token in tokens:
            token = token.strip()
            if not token:
                continue
            try:
                await self.validate_and_setup_bot(token)
            except Exception as exc:
                logger.warning("Env'dagi bot ro'yxatdan o'tmadi: %s", exc)

    async def _set_logo(self, bot: Bot) -> None:
        logo_path = self._find_logo()
        if logo_path is None:
            logger.warning("assets/ logo fayli topilmadi, profil rasm o'rnatilmadi")
            return
        temp: str | None = None
        try:
            temp = await asyncio.to_thread(self._squared_logo, logo_path)
            await bot.set_my_profile_photo(photo=FSInputFile(temp))
        except TelegramAPIError:
            logger.warning("Profil rasm o'rnatish amalga oshmadi (davom ettiriladi)")
        except Exception:
            logger.warning(
                "Logo faylini qayta ishlab bo'lmadi (davom ettiriladi): %s",
                logo_path,
                exc_info=True,
            )
        finally:
            if temp is not None:
                try:
                    Path(temp).unlink(missing_ok=True)
                except OSError:
                    pass

    @staticmethod
    def _find_logo() -> Path | None:
        for name in LOGO_GLOBS:
            candidate = ASSETS_DIR / name
            if candidate.exists():
                return candidate
        return None

    @staticmethod
    def _squared_logo(src: Path) -> str:
        import os

        from PIL import Image, ImageOps

        suffix = src.suffix.lower() in (".jpg", ".jpeg")
        fmt = "JPEG" if suffix else "PNG"
        fd, tmp = tempfile.mkstemp(prefix="safenetuz_logo_", suffix=src.suffix)
        try:
            with Image.open(src) as image:
                image = ImageOps.exif_transpose(image).convert("RGB")
                image = ImageOps.fit(image, (LOGO_SIZE, LOGO_SIZE), method=Image.LANCZOS)
                image.save(tmp, format=fmt)
        finally:
            os.close(fd)
        return tmp

    async def _start_polling(self, bot: Bot) -> None:
        dp = self._build_dispatcher()
        task = asyncio.create_task(dp.start_polling(bot))
        task.add_done_callback(self._on_polling_done)
        self._tasks.append(task)

    def _build_dispatcher(self) -> Dispatcher:
        dp = Dispatcher()
        for router in self._routers:
            dp.include_router(router)
        return dp

    async def feed_update(self, bot_token: str, update) -> bool:
        dp = self._dispatchers.get(bot_token)
        if dp is None:
            return False
        await dp.feed_update(self._bots[bot_token], update)
        return True

    def _on_polling_done(self, task: asyncio.Task) -> None:
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            logger.error("Mirror bot polling xatosi: %s", exc, exc_info=True)

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        self._tasks.clear()
        for bot in self._bots.values():
            await bot.session.close()
        self._bots.clear()


_manager: MirrorManager | None = None


def get_mirror_manager(routers: Iterable = (), webhook_domain: str | None = None) -> MirrorManager:
    global _manager
    if _manager is None:
        _manager = MirrorManager(routers=routers, webhook_domain=webhook_domain)
    return _manager