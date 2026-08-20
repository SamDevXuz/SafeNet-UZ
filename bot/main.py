import asyncio
import logging

from aiogram import Bot, Dispatcher

from bot.handlers import analyze, group_guard, mirror, start
from core.config import get_settings
from core.mirror_manager import get_mirror_manager
from database.cache import init_cache
from database.session import init_database


async def main() -> None:
    settings = get_settings()

    logging.basicConfig(
        level=settings.log_level_upper,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )

    if settings.database_url.startswith("sqlite"):
        from pathlib import Path

        db_file = settings.database_url.split("///", 1)[1]
        Path(db_file).parent.mkdir(parents=True, exist_ok=True)

    database = init_database(settings.database_url)
    await database.connect()

    cache = init_cache(
        url=settings.redis_url,
        ttl_clean=settings.cache_ttl_clean,
        ttl_malicious=settings.cache_ttl_malicious,
    )

    manager = get_mirror_manager(
        routers=[
            start.router,
            mirror.router,
            group_guard.router,
            analyze.router,
        ],
        webhook_domain=settings.mirror_webhook_domain,
    )
    await manager.register_tokens_from_env(
        settings.mirror_bots.split(",") if settings.mirror_bots else ()
    )

    bot = Bot(token=settings.bot_token.get_secret_value())
    dp = Dispatcher()

    dp.include_router(start.router)
    dp.include_router(mirror.router)
    dp.include_router(analyze.router)

    try:
        await dp.start_polling(bot)
    finally:
        await manager.stop()
        await bot.session.close()
        await database.close()
        await cache.close()


if __name__ == "__main__":
    asyncio.run(main())