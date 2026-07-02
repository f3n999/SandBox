"""
Tâches Celery pour CAPE Sandbox.

Les analyses CAPE prennent 2 à 10 minutes — on ne peut pas tenir une connexion
HTTP ouverte tout ce temps. Le pattern :

  1. Client appelle /api/v1/upload → la route soumet la tâche Celery → retourne 202 + task_id
  2. Worker Celery exécute analyze_with_cape() → stocke le résultat en Redis (backend)
  3. Client poll /api/v1/verdict/{task_id} → lit le résultat depuis Redis
"""
from __future__ import annotations

import asyncio
import base64
import logging
from typing import Optional

from celery import Task

from orchestrator.celery_app import celery_app
from orchestrator.core.config import get_settings
from orchestrator.core.filetype import is_detonable, static_type_score, compute_imphash
from orchestrator.services.cache import CacheService
from orchestrator.services.cape_client import CAPEClient
from orchestrator.services.clamav_client import ClamAVClient
from orchestrator.services.yara_scanner import YaraScanner
from orchestrator.models.schemas import Verdict

logger = logging.getLogger(__name__)


class CapeTask(Task):
    """Base task — réutilise les clients entre les exécutions du worker."""
    _cape: Optional[CAPEClient] = None
    _yara: Optional[YaraScanner] = None
    _clamav: Optional[ClamAVClient] = None
    _cache: Optional[CacheService] = None

    @property
    def cape(self) -> CAPEClient:
        if self._cape is None:
            s = get_settings()
            self._cape = CAPEClient(
                cape_url=s.cape_api_url,
                api_token=s.cape_api_token,
                timeout=s.cape_timeout,
            )
        return self._cape

    @property
    def yara(self) -> YaraScanner:
        if self._yara is None:
            s = get_settings()
            self._yara = YaraScanner(
                rules_path=s.yara.rules_path,
                enabled=s.yara.enabled,
                timeout=s.yara.timeout,
            )
            try:
                self._yara.load()
            except Exception as exc:  # noqa: BLE001
                logger.warning("YARA load failed in worker : %s", exc)
        return self._yara

    @property
    def clamav(self) -> ClamAVClient:
        if self._clamav is None:
            s = get_settings()
            self._clamav = ClamAVClient(
                host=s.clamav.host,
                port=s.clamav.port,
                unix_socket=s.clamav.unix_socket,
                timeout=s.clamav.timeout,
                enabled=s.clamav.enabled,
            )
        return self._clamav

    @property
    def cache(self) -> CacheService:
        if self._cache is None:
            s = get_settings()
            self._cache = CacheService(redis_url=s.redis_url)
        return self._cache


@celery_app.task(
    bind=True,
    base=CapeTask,
    name="cape.analyze_attachment",
    autoretry_for=(ConnectionError,),
    retry_kwargs={"max_retries": 3, "countdown": 30},
    soft_time_limit=600,
    time_limit=900,
)
def analyze_attachment_task(
    self, sha256: str, filename: str, content_b64: str
) -> dict:
    """
    Tâche d'analyse complète d'une pièce jointe (YARA → ClamAV → CAPE).
    Retourne un dict sérialisable (stocké comme result Celery).
    """
    try:
        content = base64.b64decode(content_b64)
    except Exception as exc:
        logger.error("Décodage base64 échoué : %s", exc)
        return {
            "sha256": sha256, "verdict": Verdict.ERROR.value,
            "error": "invalid base64 payload",
        }

    return asyncio.run(_run_async(self, sha256, filename, content))


async def _run_async(
    task: CapeTask, sha256: str, filename: str, content: bytes
) -> dict:
    """Pipeline worker avec gating CAPE.

    Ordre : dédup exacte → YARA → ClamAV → score statique → gate zone-grise
            → pré-filtre type → dédup floue → CAPE.
    CAPE n'est appelé QUE pour la zone grise + type détonable + jamais vu.
    """
    await task.cache.connect()
    s = get_settings()

    # ── 0) DÉDUP EXACTE (SHA256) — déjà analysé → 0 détonation ─────────────
    cached = await task.cache.get_hash_verdict(sha256)
    if cached:
        return _from_cache(sha256, cached, source="cache")

    # ── 1) YARA — block direct si forte confiance ──────────────────────────
    yara_score = 0.0
    yara_threat: Optional[str] = None
    yara_rules: list[str] = []
    if task.yara.enabled and task.yara.health_check():
        y = await task.yara.scan_bytes(content)
        if y.matched:
            yara_score, yara_threat, yara_rules = y.score, y.threat_name, y.rule_names
            if y.score >= 0.90:
                return await _block(
                    task, sha256, y.threat_name, y.score,
                    [f"yara:{r}" for r in y.rule_names], "yara",
                )

    # ── 2) ClamAV — block direct si infecté ────────────────────────────────
    if task.clamav.enabled:
        c = await task.clamav.scan_bytes(content)
        if c.infected:
            return await _block(
                task, sha256, f"ClamAV/{c.signature}", 1.0,
                [f"clamav:{c.signature}"], "clamav",
            )

    # ── 3) SCORE STATIQUE COMBINÉ ──────────────────────────────────────────
    combined = max(yara_score, static_type_score(filename, content))

    # ── 4) GATE ZONE-GRISE — on ne détone QUE l'incertain ──────────────────
    # Strictement < (pas <=) : même faille que le chemin sync (orchestrator.py)
    # — sur la borne exacte, <= laissait passer en ALLOW sans détonation.
    if combined < s.score_threshold_allow:                 # <0.3 → propre
        return await _finalize(task, sha256, Verdict.ALLOW, combined, None, [], "static")
    if combined >= s.score_threshold_block:               # ≥0.8 → bloqué (ex. via MISP)
        return await _block(
            task, sha256, yara_threat or "static/high-risk", combined,
            [f"yara:{r}" for r in yara_rules], "static",
        )

    # ── 5) PRÉ-FILTRE TYPE — un fichier inerte ne se détone pas ────────────
    if not is_detonable(filename, content):
        # Zone grise MAIS pas de contenu actif → verdict prudent, sans CAPE.
        verdict = Verdict.SUSPECT if combined >= s.score_threshold_suspect else Verdict.ALLOW
        return await _finalize(task, sha256, verdict, combined, None, [], "static-inert")

    # ── 6) DÉDUP FLOUE (imphash) — variante déjà détonée → réutilise ───────
    imphash = compute_imphash(content)
    if imphash:
        fuzzy = await task.cache.get_hash_verdict(f"imp:{imphash}")
        if fuzzy:
            return _from_cache(sha256, fuzzy, source="fuzzy-cache")

    # ── 7) CAPE — la minorité : zone grise + type détonable + jamais vu ────
    # Verrou anti-duplication — même mécanisme que le chemin sync
    # (orchestrator.py). NE PAS passer par _finalize ici : ça cacherait le
    # verdict "prudent" avec un TTL de 7 jours et empêcherait le VRAI
    # verdict du gagnant d'être vu par les analyses suivantes de ce hash.
    claimed = await task.cache.try_acquire_lock(
        f"cape:inflight:{sha256}", ttl=s.cape_timeout + 60,
    )
    if not claimed:
        logger.info(
            "CAPE déjà en cours ailleurs pour %s… — skip soumission dupliquée",
            sha256[:12],
        )
        return {
            "sha256": sha256, "verdict": Verdict.SUSPECT.value, "confidence": combined,
            "threat_name": None, "signatures": [], "source": "cape-inflight-elsewhere",
        }

    result = await task.cape.analyze_and_verdict(
        content, filename, max_wait=s.cape_timeout,
    )
    verdict_obj = result.get("verdict", Verdict.ERROR)
    if not isinstance(verdict_obj, Verdict):
        verdict_obj = Verdict(verdict_obj)

    await task.cache.set_hash_verdict(
        sha256, verdict_obj,
        threat_name=result.get("threat_name"),
        confidence=result.get("confidence", 0.0),
        source="cape", ttl=86400 * 7,
    )
    if imphash:  # mémorise le verdict pour les futures variantes proches
        await task.cache.set_hash_verdict(
            f"imp:{imphash}", verdict_obj,
            threat_name=result.get("threat_name"),
            confidence=result.get("confidence", 0.0),
            source="cape", ttl=86400 * 7,
        )

    return {
        "sha256": sha256,
        "verdict": verdict_obj.value,
        "confidence": result.get("confidence", 0.0),
        "cape_score": result.get("cape_score", 0.0),
        "threat_name": result.get("threat_name"),
        "signatures": result.get("signatures_matched", []),
        "cape_task_id": result.get("cape_task_id"),
        "source": "cape",
    }


# ──────────────────── Helpers de gating ────────────────────

async def _block(
    task: CapeTask, sha256: str, threat: Optional[str], conf: float,
    sigs: list[str], source: str,
) -> dict:
    """Verdict BLOCK : met en cache et retourne le dict sérialisable."""
    await task.cache.set_hash_verdict(
        sha256, Verdict.BLOCK, threat_name=threat, confidence=conf,
        source=source, ttl=86400 * 7,
    )
    return {
        "sha256": sha256, "verdict": Verdict.BLOCK.value, "confidence": conf,
        "threat_name": threat, "signatures": sigs, "source": source,
    }


async def _finalize(
    task: CapeTask, sha256: str, verdict: Verdict, conf: float,
    threat: Optional[str], sigs: list[str], source: str,
) -> dict:
    """Verdict non-bloquant tranché sans CAPE (ALLOW / SUSPECT)."""
    await task.cache.set_hash_verdict(
        sha256, verdict, threat_name=threat, confidence=conf,
        source=source, ttl=86400 * 7,
    )
    return {
        "sha256": sha256, "verdict": verdict.value, "confidence": conf,
        "threat_name": threat, "signatures": sigs, "source": source,
    }


def _from_cache(sha256: str, cached: dict, source: str) -> dict:
    """Reconstruit un dict de réponse depuis un hit cache (exact ou flou)."""
    return {
        "sha256": sha256,
        "verdict": cached.get("verdict", Verdict.ERROR.value),
        "confidence": cached.get("confidence", 0.0),
        "threat_name": cached.get("threat_name"),
        "signatures": [],
        "source": source,
    }
