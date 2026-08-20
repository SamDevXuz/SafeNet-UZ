import json
import logging
from typing import Any

import redis.asyncio as aioredis

from database.models import STATUS_MALICIOUS

logger = logging.getLogger(__name__)

URL_CACHE_PREFIX = "safenetuz:url:"
APK_CACHE_PREFIX = "safenetuz:apk:"

DEFAULT_TTL_CLEAN = 86400
DEFAULT_TTL_MALICIOUS = 2592000


class RedisCache:
    def __init__(
        self,
        url: str | None = None,
        *,
        client: Any | None = None,
        ttl_clean: int = DEFAULT_TTL_CLEAN,
        ttl_malicious: int = DEFAULT_TTL_MALICIOUS,
    ) -> None:
        self._url = url
        self._client = client
        self._owns_client = client is None
        self.ttl_clean = int(ttl_clean)
        self.ttl_malicious = int(ttl_malicious)

    async def _get_client(self) -> Any | None:
        if self._client is not None:
            return self._client
        if not self._url:
            return None
        try:
            self._client = aioredis.from_url(self._url, decode_responses=True)
        except Exception as exc:
            logger.warning("Redis ulanish xatosi: %s", exc)
            return None
        return self._client

    def _ttl_for(self, status: str) -> int:
        return self.ttl_malicious if status == STATUS_MALICIOUS else self.ttl_clean

    async def get(self, key: str) -> dict | None:
        client = await self._get_client()
        if client is None:
            return None
        try:
            raw = await client.get(key)
        except Exception as exc:
            logger.warning("Redis GET xatosi (%s): %s", key, exc)
            return None
        if not raw:
            return None
        try:
            data = json.loads(raw)
            if not isinstance(data, dict):
                return None
        except (ValueError, TypeError):
            logger.warning("Kesh ma'lumot buzuq formatda: %s", key)
            return None
        return data

    async def set(self, key: str, payload: dict, status: str) -> None:
        client = await self._get_client()
        if client is None:
            return
        try:
            await client.set(
                key,
                json.dumps(payload, ensure_ascii=False),
                ex=self._ttl_for(status),
            )
        except Exception as exc:
            logger.warning("Redis SET xatosi (%s): %s", key, exc)

    async def get_url(self, url_hash: str) -> dict | None:
        return await self.get(f"{URL_CACHE_PREFIX}{url_hash}")

    async def set_url(self, url_hash: str, payload: dict, status: str) -> None:
        await self.set(f"{URL_CACHE_PREFIX}{url_hash}", payload, status)

    async def get_apk(self, file_hash: str) -> dict | None:
        return await self.get(f"{APK_CACHE_PREFIX}{file_hash}")

    async def set_apk(self, file_hash: str, payload: dict, status: str) -> None:
        await self.set(f"{APK_CACHE_PREFIX}{file_hash}", payload, status)

    async def delete(self, key: str) -> None:
        client = await self._get_client()
        if client is None:
            return
        try:
            await client.delete(key)
        except Exception as exc:
            logger.warning("Redis DELETE xatosi (%s): %s", key, exc)

    async def close(self) -> None:
        if self._owns_client and self._client is not None:
            try:
                await self._client.aclose()
            except Exception as exc:
                logger.warning("Redis yopish xatosi: %s", exc)
            self._client = None


_cache: RedisCache | None = None


def init_cache(
    url: str | None = None,
    *,
    ttl_clean: int = DEFAULT_TTL_CLEAN,
    ttl_malicious: int = DEFAULT_TTL_MALICIOUS,
    client: Any | None = None,
) -> RedisCache:
    global _cache
    _cache = RedisCache(
        url=url, client=client, ttl_clean=ttl_clean, ttl_malicious=ttl_malicious
    )
    return _cache


def get_cache() -> RedisCache:
    if _cache is None:
        raise RuntimeError("Kesh hali boshlanmagan: init_cache() chaqirilmagan")
    return _cache