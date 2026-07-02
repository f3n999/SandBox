"""
Tests de la primitive de verrou distribué (CacheService.try_acquire_lock /
renew_lock) — le mécanisme qui sous-tend le fix "scheduler tourne 4x" et
"même hash soumis 4x à CAPE en parallèle".

Utilise un faux client Redis minimal qui reproduit la sémantique SET NX EX
(sans dépendance à un vrai serveur Redis).
"""
from __future__ import annotations

import pytest

from orchestrator.services.cache import CacheService


class _FakeRedis:
    """Reproduit juste assez de redis.asyncio pour tester try_acquire_lock."""

    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    async def set(self, name, value, ex=None, nx=False, **_):
        if nx and name in self._store:
            return None  # échec — clé déjà posée, comme le vrai SET NX
        self._store[name] = value
        return True

    async def expire(self, name, ttl):
        return name in self._store

    def delete_key(self, name):
        self._store.pop(name, None)


@pytest.fixture
def cache():
    svc = CacheService()
    svc._redis = _FakeRedis()
    return svc


@pytest.mark.asyncio
class TestDistributedLock:
    async def test_first_caller_acquires(self, cache):
        assert await cache.try_acquire_lock("k1", ttl=60) is True

    async def test_second_caller_on_same_key_fails(self, cache):
        """C'est LA propriété qui empêche 4 workers de tous croire qu'ils
        sont seuls à soumettre le même hash à CAPE en même temps."""
        assert await cache.try_acquire_lock("k1", ttl=60) is True
        assert await cache.try_acquire_lock("k1", ttl=60) is False

    async def test_different_keys_are_independent(self, cache):
        assert await cache.try_acquire_lock("k1", ttl=60) is True
        assert await cache.try_acquire_lock("k2", ttl=60) is True

    async def test_lock_released_can_be_reacquired(self, cache):
        """Simule l'expiration TTL — une fois la clé partie, un autre
        process (ou le même après redémarrage) peut reprendre le verrou."""
        await cache.try_acquire_lock("k1", ttl=60)
        cache._redis.delete_key("k1")
        assert await cache.try_acquire_lock("k1", ttl=60) is True

    async def test_redis_error_fails_open(self, cache, monkeypatch):
        """Un souci Redis ne doit jamais bloquer le pipeline — fail-open,
        pas fail-closed (voir commentaire dans cache.py)."""
        async def _boom(*a, **kw):
            raise ConnectionError("redis down")
        cache._redis.set = _boom
        assert await cache.try_acquire_lock("k1", ttl=60) is True

    async def test_renew_lock_does_not_raise_on_missing_key(self, cache):
        """renew_lock sur une clé absente/expirée = no-op silencieux."""
        await cache.renew_lock("never-acquired", ttl=60)  # ne doit pas lever
