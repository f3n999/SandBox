"""
Service d'orchestration principal.
Pipeline de décision : Cache → Heuristique → MISP → CAPE.
C'est le cerveau du système.
"""
import uuid
import time
import logging
from typing import Optional

from orchestrator.core.heuristics import HeuristicEngine
from orchestrator.services.cache import CacheService
from orchestrator.services.cape_client import CAPEClient
from orchestrator.services.misp_client import MISPClient
from orchestrator.models.schemas import (
    AnalysisRequest, AnalysisResponse, AttachmentVerdict,
    RiskScore, Verdict, AnalysisStage,
)

logger = logging.getLogger(__name__)


class OrchestratorService:
    """
    Pipeline d'analyse en cascade :
    1. Cache Redis (instantané)
    2. Heuristique (< 10ms)
    3. MISP lookup (< 1s)
    4. [Optionnel] CAPE Sandbox (2-10 min)

    Chaque étape peut court-circuiter le pipeline avec un verdict définitif.
    """

    def __init__(
        self,
        cache: CacheService,
        heuristic: HeuristicEngine,
        misp: MISPClient,
        cape: CAPEClient,
        score_threshold_allow: float = 0.3,
        score_threshold_suspect: float = 0.6,
        score_threshold_block: float = 0.8,
    ):
        self.cache = cache
        self.heuristic = heuristic
        self.misp = misp
        self.cape = cape
        self.threshold_allow = score_threshold_allow
        self.threshold_suspect = score_threshold_suspect
        self.threshold_block = score_threshold_block

    async def analyze(self, request: AnalysisRequest) -> AnalysisResponse:
        """
        Pipeline d'analyse principal.
        Retourne un verdict le plus vite possible.
        """
        task_id = str(uuid.uuid4())
        start_time = time.monotonic()

        logger.info(
            f"[{task_id}] Analysis started | agent={request.agent_id} | "
            f"sender={request.email.sender} | attachments={len(request.attachments)}"
        )

        attachment_verdicts: list[AttachmentVerdict] = []
        worst_verdict = Verdict.ALLOW
        requires_upload = False

        for attachment in request.attachments:
            result = await self._analyze_single_attachment(
                task_id, request, attachment
            )
            attachment_verdicts.append(result["verdict_obj"])

            # Track le pire verdict
            if self._verdict_severity(result["verdict_obj"].verdict) > self._verdict_severity(worst_verdict):
                worst_verdict = result["verdict_obj"].verdict

            if result.get("requires_upload"):
                requires_upload = True

        # Mise à jour réputation expéditeur
        is_blocked = worst_verdict in (Verdict.BLOCK, Verdict.QUARANTINE)
        await self.cache.update_sender_reputation(
            request.email.sender_domain, blocked=is_blocked
        )

        elapsed_ms = int((time.monotonic() - start_time) * 1000)

        # Déterminer le stage final
        if requires_upload:
            stage = AnalysisStage.CAPE_SUBMITTED
        elif worst_verdict == Verdict.PENDING:
            stage = AnalysisStage.HEURISTIC
        else:
            stage = AnalysisStage.VERDICT_READY

        response = AnalysisResponse(
            task_id=task_id,
            overall_verdict=worst_verdict,
            stage=stage,
            attachments=attachment_verdicts,
            requires_file_upload=requires_upload,
            analysis_time_ms=elapsed_ms,
            message=self._verdict_message(worst_verdict),
        )

        logger.info(
            f"[{task_id}] Analysis complete | verdict={worst_verdict.value} | "
            f"time={elapsed_ms}ms | requires_upload={requires_upload}"
        )

        return response

    async def _analyze_single_attachment(
        self,
        task_id: str,
        request: AnalysisRequest,
        attachment,
    ) -> dict:
        """Analyse une pièce jointe à travers le pipeline en cascade."""

        sha = attachment.sha256

        # ──── Étape 1 : Cache Redis ────
        cached = await self.cache.get_hash_verdict(sha)
        if cached:
            v = Verdict(cached["verdict"])
            logger.info(f"[{task_id}] {sha[:12]}... CACHE HIT → {v.value}")
            return {
                "verdict_obj": AttachmentVerdict(
                    sha256=sha,
                    verdict=v,
                    confidence=cached.get("confidence", 0.9),
                    threat_name=cached.get("threat_name"),
                    signatures_matched=[],
                    analysis_source="cache",
                ),
                "requires_upload": False,
            }

        # ──── Étape 2 : Heuristique ────
        risk = self.heuristic.compute_risk(request)
        heuristic_score = risk.total

        logger.info(f"[{task_id}] {sha[:12]}... heuristic_score={heuristic_score:.3f}")

        # Si score heuristique très élevé → bloquer directement
        if heuristic_score >= self.threshold_block:
            verdict = Verdict.BLOCK
            await self.cache.set_hash_verdict(
                sha, verdict, confidence=heuristic_score, source="heuristic"
            )
            return {
                "verdict_obj": AttachmentVerdict(
                    sha256=sha,
                    verdict=verdict,
                    confidence=heuristic_score,
                    threat_name="Heuristic/HighRisk",
                    signatures_matched=risk.breakdown.get("reasons", []),
                    analysis_source="heuristic",
                ),
                "requires_upload": False,
            }

        # ──── Étape 3 : MISP Lookup ────
        misp_result = await self.misp.search_hash(sha)
        if misp_result.get("found"):
            risk.misp_score = misp_result["misp_score"]
            risk.compute_total()

            logger.info(f"[{task_id}] {sha[:12]}... MISP HIT → score={risk.total:.3f}")

            if risk.total >= self.threshold_block:
                verdict = Verdict.BLOCK
                await self.cache.set_hash_verdict(
                    sha, verdict,
                    threat_name=misp_result.get("threat_name"),
                    confidence=risk.total,
                    source="misp",
                )
                return {
                    "verdict_obj": AttachmentVerdict(
                        sha256=sha,
                        verdict=verdict,
                        confidence=risk.total,
                        threat_name=misp_result.get("threat_name"),
                        signatures_matched=misp_result.get("tags", [])[:10],
                        analysis_source="misp",
                    ),
                    "requires_upload": False,
                }

        # ──── Étape 4 : Décision — CAPE ou pas ? ────
        combined_score = risk.total

        if combined_score <= self.threshold_allow:
            # Score faible → ALLOW
            verdict = Verdict.ALLOW
            await self.cache.set_hash_verdict(
                sha, verdict, confidence=1.0 - combined_score, source="heuristic+misp"
            )
            return {
                "verdict_obj": AttachmentVerdict(
                    sha256=sha,
                    verdict=verdict,
                    confidence=1.0 - combined_score,
                    analysis_source="heuristic+misp",
                ),
                "requires_upload": False,
            }

        # Score intermédiaire → demander analyse CAPE
        logger.info(
            f"[{task_id}] {sha[:12]}... score={combined_score:.3f} → requesting CAPE analysis"
        )
        return {
            "verdict_obj": AttachmentVerdict(
                sha256=sha,
                verdict=Verdict.REQUEST_DEEP_ANALYSIS,
                confidence=combined_score,
                signatures_matched=risk.breakdown.get("reasons", []),
                analysis_source="heuristic+misp",
            ),
            "requires_upload": True,
        }

    async def analyze_with_cape(
        self, task_id: str, sha256: str, file_data: bytes, filename: str
    ) -> AttachmentVerdict:
        """
        Analyse CAPE (chemin profond).
        Appelé quand l'agent envoie le fichier complet.
        """
        logger.info(f"[{task_id}] Starting CAPE analysis for {sha256[:12]}...")

        result = await self.cape.analyze_and_verdict(file_data, filename)

        verdict = result.get("verdict", Verdict.ERROR)
        if isinstance(verdict, str):
            verdict = Verdict(verdict)

        # Mettre en cache le résultat CAPE
        await self.cache.set_hash_verdict(
            sha256,
            verdict,
            threat_name=result.get("threat_name"),
            confidence=result.get("confidence", 0.0),
            source="cape",
            ttl=86400 * 7,  # 7 jours pour résultat CAPE
        )

        return AttachmentVerdict(
            sha256=sha256,
            verdict=verdict,
            confidence=result.get("confidence", 0.0),
            threat_name=result.get("threat_name"),
            signatures_matched=result.get("signatures_matched", []),
            analysis_source="cape",
        )

    # ──────────────────── Helpers ────────────────────

    @staticmethod
    def _verdict_severity(verdict: Verdict) -> int:
        """Ordre de sévérité pour comparer les verdicts."""
        order = {
            Verdict.ALLOW: 0,
            Verdict.PENDING: 1,
            Verdict.SUSPECT: 2,
            Verdict.REQUEST_DEEP_ANALYSIS: 3,
            Verdict.QUARANTINE: 4,
            Verdict.BLOCK: 5,
            Verdict.ERROR: 6,
            Verdict.TIMEOUT: 6,
        }
        return order.get(verdict, 0)

    @staticmethod
    def _verdict_message(verdict: Verdict) -> str:
        messages = {
            Verdict.ALLOW: "Email autorisé — aucune menace détectée",
            Verdict.BLOCK: "Email bloqué — menace détectée",
            Verdict.QUARANTINE: "Email mis en quarantaine — comportement suspect",
            Verdict.SUSPECT: "Email suspect — surveillance renforcée",
            Verdict.REQUEST_DEEP_ANALYSIS: "Analyse approfondie requise — envoyez le fichier",
            Verdict.PENDING: "Analyse en cours",
            Verdict.ERROR: "Erreur lors de l'analyse",
            Verdict.TIMEOUT: "Analyse interrompue — timeout dépassé",
        }
        return messages.get(verdict, "")
