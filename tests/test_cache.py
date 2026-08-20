import fakeredis
import pytest

import database.cache as cache_module
from database.cache import RedisCache
from database.models import STATUS_CLEAN, STATUS_MALICIOUS


@pytest.fixture
def client():
    return fakeredis.aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
async def redis_cache(client):
    cache = RedisCache(client=client, ttl_clean=100, ttl_malicious=500)
    yield cache


async def test_set_get_roundtrip(redis_cache, client):
    assert await redis_cache.get_url("h1") is None
    await redis_cache.set_url("h1", {"verdict": "XAVFLI", "status": "malicious"}, STATUS_MALICIOUS)
    payload = await redis_cache.get_url("h1")
    assert payload == {"verdict": "XAVFLI", "status": "malicious"}


async def test_ttl_depends_on_status(redis_cache, client):
    await redis_cache.set_url("clean-key", {"status": "clean"}, STATUS_CLEAN)
    await redis_cache.set_url("bad-key", {"status": "malicious"}, STATUS_MALICIOUS)
    assert await client.ttl("safenetuz:url:clean-key") == 100
    assert await client.ttl("safenetuz:url:bad-key") == 500


async def test_get_missing_returns_none(redis_cache):
    assert await redis_cache.get_url("missing") is None
    assert await redis_cache.get_apk("missing") is None


async def test_get_malformed_json_returns_none(redis_cache, client):
    await client.set("safenetuz:url:bad", "not-json")
    assert await redis_cache.get_url("bad") is None


async def test_get_non_dict_json_returns_none(redis_cache, client):
    await client.set("safenetuz:url:list", "[1, 2]")
    assert await redis_cache.get_url("list") is None


async def test_apk_set_get(redis_cache):
    await redis_cache.set_apk("apk-hash", {"status": "clean", "file_name": "x.apk"}, STATUS_CLEAN)
    assert await redis_cache.get_apk("apk-hash") == {"status": "clean", "file_name": "x.apk"}


async def test_network_error_is_non_fatal():
    class BrokenClient:
        async def get(self, key):
            raise TimeoutError("redis down")

        async def set(self, key, value, ex=None):
            raise TimeoutError("redis down")

    cache = RedisCache(client=BrokenClient())
    assert await cache.get_url("x") is None
    await cache.set_url("x", {"status": "clean"}, STATUS_CLEAN)


async def test_no_client_no_url_is_safe():
    cache = RedisCache()
    assert await cache.get_url("x") is None
    await cache.set_url("x", {"status": "clean"}, STATUS_CLEAN)


async def test_delete(redis_cache, client):
    await redis_cache.set_url("key", {"status": "clean"}, STATUS_CLEAN)
    await redis_cache.delete("safenetuz:url:key")
    assert await redis_cache.get_url("key") is None


async def test_init_and_get_cache_globals(monkeypatch, client):
    monkeypatch.setattr(cache_module, "_cache", None)
    cache = cache_module.init_cache(client=client, ttl_clean=1, ttl_malicious=2)
    assert cache_module.get_cache() is cache
    assert cache.ttl_clean == 1
    assert cache.ttl_malicious == 2
    monkeypatch.setattr(cache_module, "_cache", None)
    with pytest.raises(RuntimeError):
        cache_module.get_cache()