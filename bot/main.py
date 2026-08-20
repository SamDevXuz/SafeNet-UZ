import asyncio
import logging

from aiogram import Bot, Dispatcher

from bot.handlers import analyze, start
from core.config import get_settings


async def main() -> None:
    settings = get_settings()

    logging.basicConfig(
        level=settings.log_level_upper,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )

    bot = Bot(token=settings.bot_token.get_secret_value())
    dp = Dispatcher()

    dp.include_router(start.router)
    dp.include_router(analyze.router)

    try:
        await dp.start_polling(bot)
    finally:
        await bot.session.close()


if __name__ == "__main__":
    asyncio.run(main())