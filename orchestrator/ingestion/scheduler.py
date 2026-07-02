"""
Scheduler — scans automatiques du tenant via Graph API.

APScheduler (AsyncIOScheduler) intégré au lifespan FastAPI :
  - lancé au startup si SCHEDULE_ENABLED=true et Azure configuré
  - scan toutes les N minutes (configurable)
  - scan différentiel : ne récupère que les emails arrivés depuis le dernier run
  - chaque run crée une ScanSession persistée en DB
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import select

from orchestrator.core.config import get_settings
from orchestrator.db.session import session_scope
from orchestrator.ingestion.graph_client import GraphClient
from orchestrator.ingestion.graph_ingestor import GraphIngestor, IngestionStats
from orchestrator.models.database import ScanSession
from orchestrator.services.orchestrator import OrchestratorService

logger = logging.getLogger(__name__)


class GraphScheduler:
    """Gestionnaire du job APScheduler."""

    def __init__(
        self,
        orchestrator: OrchestratorService,
        graph_client: GraphClient,
        tenant_id: str,
        interval_minutes: int = 15,
        emails_per_user: int = 25,
        max_users: int = 500,
        differential: bool = True,
    ):
        self.orchestrator = orchestrator
        self.graph_client = graph_client
        self.tenant_id = tenant_id
        self.interval_minutes = interval_minutes
        self.emails_per_user = emails_per_user
        self.max_users = max_users
        self.differential = differential
        self._scheduler = AsyncIOScheduler(timezone="UTC")
        self._running = False
        self._is_leader = False
        self._leader_lock_key = f"mgx:scheduler:leader:{tenant_id}"

    async def try_start(self) -> bool:
        """
        Démarre le scheduler UNIQUEMENT si ce process obtient le verrou
        Redis de leader.

        L'orchestrateur tourne avec plusieurs process (Dockerfile :
        `uvicorn --workers 4`). `lifespan()` s'exécute dans CHAQUE process
        — sans ce verrou, 4 schedulers indépendants démarraient et
        scanneraient le même tenant en parallèle, soumettant chaque pièce
        jointe 4x à CAPE (bug réel observé : ~31% des verdicts en TIMEOUT,
        la VM de détonation ne pouvant traiter qu'une tâche à la fois).

        Le verrou est renouvelé à chaque scan (`_run_scan`) avec une TTL
        plus longue que l'intervalle : si ce process meurt, le verrou
        expire et le scheduler reste simplement arrêté jusqu'au prochain
        redémarrage du conteneur (pas de reprise automatique par un autre
        worker — acceptable ici, largement préférable au bug de duplication).

        Retourne True si CE process pilote effectivement le scheduler.
        """
        if self._running:
            return True
        lock_ttl = self.interval_minutes * 60 + 120  # marge de survie entre 2 scans
        acquired = await self.orchestrator.cache.try_acquire_lock(
            self._leader_lock_key, ttl=lock_ttl,
        )
        if not acquired:
            logger.info(
                "Scheduler déjà piloté par un autre process (verrou %s) — "
                "ce worker reste passif.", self._leader_lock_key,
            )
            return False
        self._is_leader = True
        self._start_internal()
        return True

    def _start_internal(self) -> None:
        self._scheduler.add_job(
            self._run_scan,
            trigger=IntervalTrigger(minutes=self.interval_minutes),
            id="graph_tenant_scan",
            name="MailGuardianX Graph tenant scan",
            replace_existing=True,
            max_instances=1,           # Pas deux runs en parallèle
            coalesce=True,             # Fusionne les triggers en retard
            misfire_grace_time=300,
            next_run_time=datetime.now(timezone.utc),  # premier scan immédiat au démarrage
        )
        self._scheduler.start()
        self._running = True
        logger.info(
            "Scheduler démarré (intervalle=%dmin, emails/user=%d, max_users=%d)",
            self.interval_minutes, self.emails_per_user, self.max_users,
        )

    async def shutdown(self) -> None:
        if self._running:
            self._scheduler.shutdown(wait=False)
            self._running = False
            logger.info("Scheduler arrêté")

    # ────────── Job ──────────

    async def _run_scan(self) -> None:
        """Exécute un scan complet — appelé par APScheduler."""
        logger.info("=== Graph scan démarré (tenant=%s) ===", self.tenant_id)

        # Prolonge le verrou de leader — tant que ce process tourne et
        # scanne effectivement, personne d'autre ne doit pouvoir démarrer
        # un second scheduler concurrent pour ce tenant.
        lock_ttl = self.interval_minutes * 60 + 120
        await self.orchestrator.cache.renew_lock(self._leader_lock_key, ttl=lock_ttl)

        since = await self._compute_since() if self.differential else None

        ingestor = GraphIngestor(
            graph=self.graph_client,
            orchestrator=self.orchestrator,
            tenant_id=self.tenant_id,
        )

        # Crée la session DB AVANT le scan (pour avoir un ID stable)
        stats = IngestionStats()
        await self._persist_session_start(stats)

        try:
            # On RÉUTILISE le même `stats` (donc le même session_id que la
            # ScanSession persistée ci-dessus) : sinon scan_tenant créait sa
            # propre session_id et _persist_session_end ne trouvait jamais la ligne.
            stats = await ingestor.scan_tenant(
                emails_per_user=self.emails_per_user,
                max_users=self.max_users,
                since=since,
                stats=stats,
            )
        except Exception as exc:
            logger.exception("Scheduled scan failed : %s", exc)
            stats.error_count += 1
            stats.finished_at = datetime.now(timezone.utc)
        finally:
            await self._persist_session_end(stats)

        logger.info(
            "=== Scan terminé : users=%d emails=%d attachments=%d "
            "BLOCK=%d QUARANTINE=%d SUSPECT=%d ALLOW=%d errors=%d ===",
            stats.users_scanned, stats.emails_scanned, stats.attachments_scanned,
            stats.block_count, stats.quarantine_count, stats.suspect_count,
            stats.allow_count, stats.error_count,
        )

    async def trigger_now(self) -> None:
        """Déclenche un scan immédiatement (hors planning)."""
        await self._run_scan()

    # ────────── Persistance ──────────

    async def _compute_since(self) -> Optional[datetime]:
        """Récupère le started_at du dernier scan réussi pour scan différentiel."""
        async with session_scope() as db:
            stmt = (
                select(ScanSession.started_at)
                .where(ScanSession.source == "graph_scheduled")
                .where(ScanSession.tenant_id == self.tenant_id)
                .where(ScanSession.finished_at.isnot(None))
                .order_by(ScanSession.started_at.desc())
                .limit(1)
            )
            result = await db.execute(stmt)
            last = result.scalar_one_or_none()
            if last:
                # Petit overlap de 5min pour ne rien manquer
                return last - timedelta(minutes=5)
            # Premier run : 24h en arrière
            return datetime.now(timezone.utc) - timedelta(hours=24)

    async def _persist_session_start(self, stats: IngestionStats) -> None:
        async with session_scope() as db:
            session = ScanSession(
                id=stats.session_id,
                source="graph_scheduled",
                tenant_id=self.tenant_id,
                triggered_by="apscheduler",
                started_at=stats.started_at,
            )
            db.add(session)

    async def _persist_session_end(self, stats: IngestionStats) -> None:
        async with session_scope() as db:
            stmt = select(ScanSession).where(ScanSession.id == stats.session_id)
            result = await db.execute(stmt)
            session = result.scalar_one_or_none()
            if session is None:
                return
            session.finished_at = stats.finished_at or datetime.now(timezone.utc)
            session.users_scanned = stats.users_scanned
            session.emails_scanned = stats.emails_scanned
            session.attachments_scanned = stats.attachments_scanned
            session.block_count = stats.block_count
            session.quarantine_count = stats.quarantine_count
            session.suspect_count = stats.suspect_count
            session.allow_count = stats.allow_count
            session.error_count = stats.error_count
