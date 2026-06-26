"""
Orchestrateur principal — pipeline de décision en cascade.

Mode metadata-only (hash + métadonnées seuls, sans contenu) :
    Cache → Heuristique → MISP → [REQUEST_DEEP_ANALYSIS si suspect]

Mode bytes-available (ingestion M365/Graph ou /upload — chemin nominal) :
    Cache → Heuristique → YARA → ClamAV → MISP → CAPE Sandbox

Chaque étape peut court-circuiter le pipeline avec un verdict définitif
(BLOCK / ALLOW). Sinon les scores s'agrègent et la décision est prise à la fin.
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Optional

from orchestrator.core.heuristics import HeuristicEngine
from orchestrator.models.schemas import (
    AnalysisRequest, AnalysisResponse, AnalysisStage, AttachmentMetadata,
    AttachmentVerdict, RiskScore, Verdict,
)
from orchestrator.services.cache import CacheService
from orchestrator.services.cape_client import CAPEClient
from orchestrator.services.clamav_client import ClamAVClient, ClamAVResult
from orchestrator.services.misp_client import MISPClient
from orchestrator.services.yara_scanner import YaraScanner, YaraScanResult

logger = logging.getLogger(__name__)


_VERDICT_SEVERITY = {
    Verdict.ALLOW: 0,
    Verdict.PENDING: 1,
    Verdict.SUSPECT: 2,
    Verdict.REQUEST_DEEP_ANALYSIS: 3,
    Verdict.QUARANTINE: 4,
    Verdict.BLOCK: 5,
    Verdict.ERROR: 6,
    Verdict.TIMEOUT: 6,
}

_VERDICT_MESSAGES = {
    Verdict.ALLOW: "Email autorisé — aucune menace détectée",
    Verdict.BLOCK: "Email bloqué — menace confirmée",
    Verdict.QUARANTINE: "Email mis en quarantaine — comportement suspect",
    Verdict.SUSPECT: "Email suspect — surveillance renforcée",
    Verdict.REQUEST_DEEP_ANALYSIS: "Analyse approfondie requise (CAPE)",
    Verdict.PENDING: "Analyse en cours",
    Verdict.ERROR: "Erreur lors de l'analyse",
    Verdict.TIMEOUT: "Analyse interrompue — timeout dépassé",
}


class OrchestratorService:
    """Cerveau du système — orchestre tous les services d'analyse."""

    def __init__(
        self,
        cache: CacheService,
        heuristic: HeuristicEngine,
        misp: MISPClient,
        cape: CAPEClient,
        yara: Optional[YaraScanner] = None,
        clamav: Optional[ClamAVClient] = None,
        score_threshold_allow: float = 0.3,
        score_threshold_suspect: float = 0.6,
        score_threshold_block: float = 0.8,
    ):
        self.cache = cache
        self.heuristic = heuristic
        self.misp = misp
        self.cape = cape
        self.yara = yara
        self.clamav = clamav
        self.threshold_allow = score_threshold_allow
        self.threshold_suspect = score_threshold_suspect
        self.threshold_block = score_threshold_block

    # ════════════════════════════════════════════════════════════
    #  Entrée publique : metadata-only (hash seul — /api/v1/analyze)
    # ════════════════════════════════════════════════════════════

    async def analyze(self, request: AnalysisRequest) -> AnalysisResponse:
        """Analyse à partir des métadonnées seules (pas de bytes)."""
        return await self._run_pipeline(request, attachment_bytes={})

    # ════════════════════════════════════════════════════════════
    #  Entrée publique : bytes disponibles (Graph / upload)
    # ════════════════════════════════════════════════════════════

    async def analyze_with_bytes(
        self,
        request: AnalysisRequest,
        attachment_bytes: dict[str, bytes],
    ) -> AnalysisResponse:
        """Analyse avec contenu PJ disponible → YARA + ClamAV inline."""
        return await self._run_pipeline(request, attachment_bytes=attachment_bytes)

    # ════════════════════════════════════════════════════════════
    #  Pipeline principal
    # ════════════════════════════════════════════════════════════

    async def _run_pipeline(
        self,
        request: AnalysisRequest,
        attachment_bytes: dict[str, bytes],
    ) -> AnalysisResponse:
        task_id = str(uuid.uuid4())
        start = time.monotonic()
        logger.info(
            "[%s] start | sender=%s | attachments=%d | bytes_available=%d",
            task_id, request.email.sender, len(request.attachments), len(attachment_bytes),
        )

        verdicts: list[AttachmentVerdict] = []
        worst = Verdict.ALLOW
        requires_upload = False

        for att in request.attachments:
            content = attachment_bytes.get(att.sha256.lower())
            result = await self._analyze_single(task_id, request, att, content)
            verdicts.append(result["verdict_obj"])

            if _VERDICT_SEVERITY[result["verdict_obj"].verdict] > _VERDICT_SEVERITY[worst]:
                worst = result["verdict_obj"].verdict

            if result.get("requires_upload"):
                requires_upload = True

        # Réputation expéditeur
        is_blocked = worst in (Verdict.BLOCK, Verdict.QUARANTINE)
        await self.cache.update_sender_reputation(
            request.email.sender_domain, blocked=is_blocked
        )

        elapsed_ms = int((time.monotonic() - start) * 1000)

        if requires_upload:
            stage = AnalysisStage.CAPE_SUBMITTED
        elif worst == Verdict.PENDING:
            stage = AnalysisStage.HEURISTIC
        else:
            stage = AnalysisStage.VERDICT_READY

        response = AnalysisResponse(
            task_id=task_id,
            overall_verdict=worst,
            stage=stage,
            attachments=verdicts,
            requires_file_upload=requires_upload,
            analysis_time_ms=elapsed_ms,
            message=_VERDICT_MESSAGES.get(worst, ""),
        )

        # Cache du verdict global (récupérable via GET /verdict/{task_id})
        await self.cache.set_task_verdict(task_id, response.model_dump(mode="json"))

        logger.info(
            "[%s] done | verdict=%s | time=%dms | requires_upload=%s",
            task_id, worst.value, elapsed_ms, requires_upload,
        )
        return response

    # ────────────────────────────────────────────────────────
    #  Pipeline pour une pièce jointe
    # ────────────────────────────────────────────────────────

    async def _analyze_single(
        self,
        task_id: str,
        request: AnalysisRequest,
        att: AttachmentMetadata,
        content: Optional[bytes],
    ) -> dict:
        sha = att.sha256.lower()
        risk = RiskScore()
        signatures: list[str] = []
        yara_matches: list[str] = []
        clamav_sig: Optional[str] = None
        cape_task_id: Optional[int] = None

        # ── 1. Cache Redis (< 5ms) ────────────────────────────
        cached = await self.cache.get_hash_verdict(sha)
        if cached:
            v = Verdict(cached["verdict"])
            logger.info("[%s] %s… cache HIT → %s", task_id, sha[:12], v.value)
            return {
                "verdict_obj": AttachmentVerdict(
                    sha256=sha,
                    verdict=v,
                    confidence=cached.get("confidence", 0.9),
                    threat_name=cached.get("threat_name"),
                    analysis_source="cache",
                ),
                "requires_upload": False,
            }

        # ── 2. Heuristique (< 10ms) ──────────────────────────
        single_request = AnalysisRequest(
            agent_id=request.agent_id,
            hospital_id=request.hospital_id,
            email=request.email,
            attachments=[att],
        )
        heur = self.heuristic.compute_risk(single_request)
        risk.heuristic_score = heur.heuristic_score
        risk.sender_score = heur.sender_score
        signatures.extend(heur.breakdown.get("reasons", []))
        risk.compute_total()
        logger.info("[%s] %s… heuristic=%.3f", task_id, sha[:12], risk.heuristic_score)

        if risk.heuristic_score >= 0.95:  # double extension + autres = direct BLOCK
            return await self._finalize(
                sha, Verdict.BLOCK, risk, signatures, yara_matches, clamav_sig,
                threat_name="Heuristic/HighRisk", source="heuristic",
                cape_task_id=cape_task_id,
            )

        # ── 3. YARA in-memory (< 100ms, bytes requis) ────────
        if content is not None and self.yara is not None and self.yara.enabled:
            yara_result = await self.yara.scan_bytes(content)
            if yara_result.matched:
                risk.yara_score = yara_result.score
                yara_matches = yara_result.rule_names
                signatures.extend(f"yara:{r}" for r in yara_matches)
                risk.compute_total()
                logger.info(
                    "[%s] %s… YARA hits=%s score=%.2f",
                    task_id, sha[:12], yara_matches, yara_result.score,
                )
                if yara_result.score >= 0.90:
                    return await self._finalize(
                        sha, Verdict.BLOCK, risk, signatures, yara_matches, clamav_sig,
                        threat_name=yara_result.threat_name, source="yara",
                        cape_task_id=cape_task_id,
                    )

        # ── 4. ClamAV (< 500ms, bytes requis) ────────────────
        if content is not None and self.clamav is not None and self.clamav.enabled:
            cav: ClamAVResult = await self.clamav.scan_bytes(content)
            if cav.infected:
                clamav_sig = cav.signature
                risk.clamav_score = 1.0
                signatures.append(f"clamav:{clamav_sig}")
                risk.compute_total()
                logger.info("[%s] %s… ClamAV INFECTED sig=%s", task_id, sha[:12], clamav_sig)
                return await self._finalize(
                    sha, Verdict.BLOCK, risk, signatures, yara_matches, clamav_sig,
                    threat_name=f"ClamAV/{clamav_sig}", source="clamav",
                    cape_task_id=cape_task_id,
                )

        # ── 5. MISP lookup (< 1s) ────────────────────────────
        misp_result = await self.misp.search_hash(sha)
        if misp_result.get("found"):
            risk.misp_score = misp_result["misp_score"]
            risk.compute_total()
            tags = misp_result.get("tags", [])[:10]
            signatures.extend(f"misp:{t}" for t in tags)
            logger.info(
                "[%s] %s… MISP score=%.2f tags=%s",
                task_id, sha[:12], risk.misp_score, tags[:3],
            )
            if risk.misp_score >= 0.80:
                return await self._finalize(
                    sha, Verdict.BLOCK, risk, signatures, yara_matches, clamav_sig,
                    threat_name=misp_result.get("threat_name"), source="misp",
                    cape_task_id=cape_task_id,
                )

        # ── 6. Décision intermédiaire ────────────────────────
        risk.compute_total()
        combined = risk.total

        if combined >= self.threshold_block:
            return await self._finalize(
                sha, Verdict.BLOCK, risk, signatures, yara_matches, clamav_sig,
                threat_name="Aggregated/HighRisk", source="aggregated",
                cape_task_id=cape_task_id,
            )

        if combined <= self.threshold_allow:
            return await self._finalize(
                sha, Verdict.ALLOW, risk, signatures, yara_matches, clamav_sig,
                threat_name=None, source="aggregated", cape_task_id=cape_task_id,
            )

        # ── 7. CAPE inline (si bytes), sinon demander upload ─
        if content is not None:
            logger.info(
                "[%s] %s… score=%.2f → CAPE Sandbox (inline)",
                task_id, sha[:12], combined,
            )
            cape_result = await self.cape.analyze_and_verdict(content, att.filename)
            cape_verdict = cape_result.get("verdict", Verdict.SUSPECT)
            if isinstance(cape_verdict, str):
                cape_verdict = Verdict(cape_verdict)
            risk.cape_score = cape_result.get("cape_score", 0.0)
            risk.compute_total()
            cape_task_id = cape_result.get("cape_task_id")
            cape_sigs = cape_result.get("signatures_matched", [])
            signatures.extend(f"cape:{s}" for s in cape_sigs[:20])
            threat = cape_result.get("threat_name")
            return await self._finalize(
                sha, cape_verdict, risk, signatures, yara_matches, clamav_sig,
                threat_name=threat, source="cape", cape_task_id=cape_task_id,
            )

        # Pas de bytes → demander l'upload
        logger.info(
            "[%s] %s… score=%.2f → REQUEST_DEEP_ANALYSIS",
            task_id, sha[:12], combined,
        )
        return {
            "verdict_obj": AttachmentVerdict(
                sha256=sha,
                verdict=Verdict.REQUEST_DEEP_ANALYSIS,
                confidence=combined,
                signatures_matched=signatures[:30],
                analysis_source="aggregated",
                heuristic_score=risk.heuristic_score,
                misp_score=risk.misp_score,
            ),
            "requires_upload": True,
        }

    # ────────────────────────────────────────────────────────
    #  CAPE async (appelée par /api/v1/upload — upload direct d'un fichier)
    # ────────────────────────────────────────────────────────

    async def analyze_with_cape(
        self, task_id: str, sha256: str, file_data: bytes, filename: str
    ) -> AttachmentVerdict:
        """Analyse CAPE explicite (chemin profond — upload direct d'un fichier)."""
        logger.info("[%s] CAPE explicit for %s…", task_id, sha256[:12])

        # YARA + ClamAV d'abord (rapides), CAPE seulement si besoin
        if self.yara and self.yara.enabled:
            y = await self.yara.scan_bytes(file_data)
            if y.matched and y.score >= 0.90:
                await self.cache.set_hash_verdict(
                    sha256, Verdict.BLOCK,
                    threat_name=y.threat_name, confidence=y.score, source="yara",
                )
                return AttachmentVerdict(
                    sha256=sha256, verdict=Verdict.BLOCK, confidence=y.score,
                    threat_name=y.threat_name, signatures_matched=y.rule_names,
                    analysis_source="yara", yara_matches=y.rule_names,
                )
        if self.clamav and self.clamav.enabled:
            c = await self.clamav.scan_bytes(file_data)
            if c.infected:
                await self.cache.set_hash_verdict(
                    sha256, Verdict.BLOCK,
                    threat_name=f"ClamAV/{c.signature}", confidence=1.0, source="clamav",
                )
                return AttachmentVerdict(
                    sha256=sha256, verdict=Verdict.BLOCK, confidence=1.0,
                    threat_name=f"ClamAV/{c.signature}",
                    signatures_matched=[f"clamav:{c.signature}"],
                    analysis_source="clamav", clamav_signature=c.signature,
                )

        # Sinon CAPE
        result = await self.cape.analyze_and_verdict(file_data, filename)
        verdict = result.get("verdict", Verdict.ERROR)
        if isinstance(verdict, str):
            verdict = Verdict(verdict)
        await self.cache.set_hash_verdict(
            sha256, verdict, threat_name=result.get("threat_name"),
            confidence=result.get("confidence", 0.0), source="cape", ttl=86400 * 7,
        )
        return AttachmentVerdict(
            sha256=sha256,
            verdict=verdict,
            confidence=result.get("confidence", 0.0),
            threat_name=result.get("threat_name"),
            signatures_matched=result.get("signatures_matched", []),
            analysis_source="cape",
            cape_score=result.get("cape_score", 0.0),
            cape_task_id=result.get("cape_task_id"),
        )

    # ────────────────────────────────────────────────────────
    #  Helpers
    # ────────────────────────────────────────────────────────

    async def _finalize(
        self,
        sha: str,
        verdict: Verdict,
        risk: RiskScore,
        signatures: list[str],
        yara_matches: list[str],
        clamav_sig: Optional[str],
        threat_name: Optional[str],
        source: str,
        cape_task_id: Optional[int],
    ) -> dict:
        """Persiste en cache + retourne le résultat (court-circuit du pipeline)."""
        # TTL adapté selon la fiabilité du verdict
        if verdict == Verdict.BLOCK and source in ("yara", "clamav", "cape", "misp"):
            ttl = 86400 * 7         # 7 jours pour verdicts fiables
        elif verdict == Verdict.ALLOW:
            ttl = 86400             # 24h pour ALLOW
        else:
            ttl = 3600              # 1h pour les cas mous

        confidence = min(max(risk.total, 0.0), 1.0)
        await self.cache.set_hash_verdict(
            sha, verdict,
            threat_name=threat_name,
            confidence=confidence,
            source=source,
            ttl=ttl,
        )

        return {
            "verdict_obj": AttachmentVerdict(
                sha256=sha,
                verdict=verdict,
                confidence=confidence,
                threat_name=threat_name,
                signatures_matched=signatures[:30],
                analysis_source=source,
                heuristic_score=risk.heuristic_score,
                yara_matches=yara_matches,
                clamav_signature=clamav_sig,
                misp_score=risk.misp_score,
                cape_score=risk.cape_score,
                cape_task_id=cape_task_id,
            ),
            "requires_upload": False,
        }
