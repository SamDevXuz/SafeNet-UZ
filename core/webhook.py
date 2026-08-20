import logging
from typing import Any

from aiohttp import web
from aiogram.types import Update

logger = logging.getLogger(__name__)


async def process_webhook_payload(manager, bot_token: str, payload: Any) -> dict:
    if not manager.is_registered(bot_token):
        return {"ok": False, "error": "unknown bot"}
    update = Update.model_validate(payload)
    delivered = await manager.feed_update(bot_token, update)
    return {"ok": True, "delivered": delivered}


async def handle_mirror_webhook(request: web.Request) -> web.Response:
    bot_token = request.match_info["token"]
    try:
        payload = await request.json()
    except Exception:
        return web.json_response({"ok": False, "error": "invalid json"}, status=400)

    manager = request.app["mirror_manager"]
    result = await process_webhook_payload(manager, bot_token, payload)
    if not result["ok"]:
        return web.json_response(result, status=404)
    return web.json_response(result)


async def handle_health(_request: web.Request) -> web.Response:
    return web.json_response({"status": "ok"})


def create_app(manager) -> web.Application:
    app = web.Application()
    app["mirror_manager"] = manager
    app.router.add_post("/webhook/mirror/{token}", handle_mirror_webhook)
    app.router.add_get("/healthz", handle_health)
    return app


async def run_webhook_server(manager, host: str = "0.0.0.0", port: int = 8000) -> None:
    app = create_app(manager)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    logger.info("Webhook server ishga tushdi: %s:%s", host, port)