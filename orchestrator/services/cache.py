"""
Service de cache Redis.
Première étape du pipeline : lookup instantané de hash connus.
Si le hash est en cache → verdict en <5ms, pas besoin de CAPE.
"""
import json
import logging
from typing import Optional
import redis.asyncio as redis

from orchestrator.models.schemas import Verdict

logger = logging.getLogger(__name__)


class CacheService:
    """Cache Redis pour hash connus et verdicts récents."""

    def __init__(self, redis_url: str = "redis://redis:6379/0"):
        self._redis: Optional[redis.Redis] = None
        self._redis_url = redis_url

    async def connect(self):
        """Initialise la connexion Redis."""
        if self._redis is None:
            self._redis = redis.from_url(
                self._redis_url,
                encoding="utf-8",
                decode_responses=True,
            )
            # Test connexion
            await self._redis.ping()
            logger.info("Redis connected")

    async def disconnect(self):
        if self._redis:
            await self._redis.close()
            self._redis = None

    # ──────────────────── Hash Lookup ────────────────────

    async def get_hash_verdict(self, sha256: str) -> Optional[dict]:
        """
        Cherche un hash dans le cache.
        Returns: {"verdict": "block", "threat_name": "...", "confidence": 0.95, "source": "misp"}
        ou None si pas trouvé.
        """
        try:
            key = f"hash:{sha256}"
            data = await self._redis.get(key)
            if data:
                result = json.loads(data)
                # Incrémenter le hit count
                await self._redis.hincrby("hash_stats", sha256, 1)
                logger.info(f"Cache HIT for {sha256[:16]}... → {result['verdict']}")
                return result
            return None
        except Exception as e:
            logger.error(f"Redis get_hash error: {e}")
            return None

    async def set_hash_verdict(
        self,
        sha256: str,
        verdict: Verdict,
        threat_name: Optional[str] = None,
        confidence: float = 0.0,
        source: str = "unknown",
        ttl: int = 86400,
    ):
        """Enregistre un verdict de hash en cache."""
        try:
            key = f"hash:{sha256}"
            data = json.dumps({
                "verdict": verdict.value,
                "threat_name": threat_name,
                "confidence": confidence,
                "source": source,
            })
            await self._redis.setex(key, ttl, data)
            logger.info(f"Cache SET {sha256[:16]}... → {verdict.value} (TTL={ttl}s)")
        except Exception as e:
            logger.error(f"Redis set_hash error: {e}")

    # ──────────────────── Verdict Cache (par task) ────────────────────

    async def get_task_verdict(self, task_id: str) -> Optional[dict]:
        """Récupère un verdict déjà calculé pour un task_id."""
        try:
            key = f"verdict:{task_id}"
            data = await self._redis.get(key)
            return json.loads(data) if data else None
        except Exception as e:
            logger.error(f"Redis get_verdict error: {e}")
            return None

    async def set_task_verdict(self, task_id: str, verdict_data: dict, ttl: int = 3600):
        """Cache le verdict d'un task pour éviter recalcul."""
        try:
            key = f"verdict:{task_id}"
            await self._redis.setex(key, ttl, json.dumps(verdict_data))
        except Exception as e:
            logger.error(f"Redis set_verdict error: {e}")

    # ──────────────────── Rate Limiting Agents ────────────────────

    async def check_rate_limit(self, agent_id: str, max_requests: int = 100, window: int = 60) -> bool:
        """
        Rate limiting par agent.
        Returns True si la requête est autorisée.
        """
        try:
            key = f"rate:{agent_id}"
            current = await self._redis.incr(key)
            if current == 1:
                await self._redis.expire(key, window)
            return current <= max_requests
        except Exception as e:
            logger.error(f"Redis rate_limit error: {e}")
            return True  # Fail open (on ne bloque pas en cas d'erreur Redis)

    # ──────────────────── Sender Reputation (fast path) ────────────────────

    async def get_sender_reputation(self, sender_domain: str) -> Optional[dict]:
        """Lookup rapide de la réputation d'un domaine expéditeur."""
        try:
            key = f"sender:{sender_domain}"
            data = await self._redis.get(key)
            return json.loads(data) if data else None
        except Exception as e:
            logger.error(f"Redis sender_rep error: {e}")
            return None

    async def update_sender_reputation(
        self, sender_domain: str, blocked: bool, ttl: int = 86400
    ):
        """Met à jour la réputation d'un expéditeur."""
        try:
            key = f"sender:{sender_domain}"
            data = await self._redis.get(key)
            if data:
                rep = json.loads(data)
                rep["total"] = rep.get("total", 0) + 1
                if blocked:
                    rep["blocked"] = rep.get("blocked", 0) + 1
                rep["risk_ratio"] = rep["blocked"] / rep["total"]
            else:
                rep = {
                    "total": 1,
                    "blocked": 1 if blocked else 0,
                    "risk_ratio": 1.0 if blocked else 0.0,
                }
            await self._redis.setex(key, ttl, json.dumps(rep))
        except Exception as e:
            logger.error(f"Redis update_sender error: {e}")

    # ──────────────────── Health ────────────────────

    async def health_check(self) -> bool:
        """Vérifie que Redis est accessible."""
        try:
            return await self._redis.ping()
        except Exception:
            return False
