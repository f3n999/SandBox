"""
Tests d'intégration du pipeline orchestrateur.

Utilisent les vrais services HeuristicEngine + cache mocké en mémoire +
clients YARA/ClamAV/MISP/CAPE mockés. Vérifient les court-circuits et les
agrégations entre étapes.
"""
from __future__ import annotations

from unittest.mock import AsyncMock
import pytest

from orchestrator.core.heuristics import HeuristicEngine
from orchestrator.models.schemas import FileType, Verdict
from orchestrator.services.clamav_client import ClamAVResult
from orchestrator.services.orchestrator import OrchestratorService
from orchestrator.services.yara_scanner import YaraMatch, YaraScanResult


@pytest.fixture
def orchestrator(mock_cache, mock_misp, mock_cape, mock_yara, mock_clamav):
    return OrchestratorService(
        cache=mock_cache,
        heuristic=HeuristicEngine(),
        misp=mock_misp,
        cape=mock_cape,
        yara=mock_yara,
        clamav=mock_clamav,
        score_threshold_allow=0.3,
        score_threshold_suspect=0.6,
        score_threshold_block=0.8,
    )


@pytest.mark.asyncio
class TestPipelineCascade:
    async def test_cache_hit_short_circuits(self, orchestrator, mock_cache, make_request):
        """Si le hash est en cache → verdict immédiat, pas d'appel autres services."""
        request = make_request()
        sha = request.attachments[0].sha256
        await mock_cache.set_hash_verdict(
            sha, Verdict.BLOCK, threat_name="Test/Cached", confidence=0.95, source="cache",
        )

        response = await orchestrator.analyze(request)

        assert response.overall_verdict == Verdict.BLOCK
        assert response.attachments[0].analysis_source == "cache"
        assert response.attachments[0].threat_name == "Test/Cached"

    async def test_clean_email_returns_allow(self, orchestrator, make_request, make_attachment):
        """Email propre (PDF normal, SPF/DKIM pass) → ALLOW."""
        request = make_request(
            attachments=[make_attachment(file_type=FileType.PDF, filename="invoice.pdf")],
            sender="legitimate@hopital-paris.fr",
        )
        response = await orchestrator.analyze(request)
        assert response.overall_verdict == Verdict.ALLOW

    async def test_high_heuristic_short_circuits(self, orchestrator, make_request, make_attachment):
        """Heuristique très élevée (double ext + auth fail) → BLOCK direct."""
        request = make_request(
            attachments=[make_attachment(
                filename="invoice.pdf.exe",
                file_type=FileType.EXE,
                is_encrypted=True,
            )],
            sender="invoice-payment@suspicious.ru",
            spf="fail", dkim="fail", dmarc="fail",
        )
        response = await orchestrator.analyze(request)
        assert response.overall_verdict == Verdict.BLOCK

    async def test_misp_hit_blocks(self, orchestrator, mock_misp, make_request, make_attachment):
        """MISP renvoie un IOC malveillant → BLOCK."""
        mock_misp.search_hash = AsyncMock(return_value={
            "found": True,
            "misp_score": 0.95,
            "threat_name": "MISP/Emotet",
            "tags": ["ransomware:emotet"],
        })
        request = make_request(
            attachments=[make_attachment(file_type=FileType.DOC, sha256="b" * 64)],
            sender="suspicious@evil.com",
        )
        response = await orchestrator.analyze(request)
        assert response.overall_verdict == Verdict.BLOCK
        assert response.attachments[0].analysis_source == "misp"

    async def test_intermediate_score_requests_upload(
        self, orchestrator, make_request, make_attachment
    ):
        """Score intermédiaire sans bytes → REQUEST_DEEP_ANALYSIS."""
        request = make_request(
            attachments=[make_attachment(
                file_type=FileType.DOCM,
                is_macro_enabled=True,
                filename="invoice.docm",
            )],
            sender="invoice-payment@gmail.com",
            spf="softfail", dkim="none",
        )
        response = await orchestrator.analyze(request)
        assert response.requires_file_upload is True
        assert response.attachments[0].verdict == Verdict.REQUEST_DEEP_ANALYSIS


@pytest.mark.asyncio
class TestPipelineWithBytes:
    async def test_yara_match_short_circuits(
        self, orchestrator, mock_yara, make_request, make_attachment
    ):
        """YARA matche → BLOCK sans appeler ClamAV/MISP/CAPE."""
        mock_yara.enabled = True
        mock_yara.scan_bytes = AsyncMock(return_value=YaraScanResult(
            matched=True,
            matches=[YaraMatch(rule="Ransomware_CryptoAPI_Usage", tags=["ransomware"],
                              meta={"severity": "critical"})],
            score=0.95,
            threat_name="YARA/Ransomware_CryptoAPI_Usage",
        ))

        # file_type OTHER (heuristique basse) pour que le pipeline atteigne YARA
        # sans court-circuiter sur l'heuristique (un .exe bloque avant à 0.95).
        request = make_request(
            attachments=[make_attachment(file_type=FileType.OTHER, sha256="c" * 64)],
            sender="x@y.com",
        )
        bytes_map = {"c" * 64: b"MZ\x90\x00malicious content"}
        response = await orchestrator.analyze_with_bytes(request, bytes_map)

        assert response.overall_verdict == Verdict.BLOCK
        assert response.attachments[0].analysis_source == "yara"
        assert "Ransomware_CryptoAPI_Usage" in response.attachments[0].yara_matches

    async def test_clamav_infected_blocks(
        self, orchestrator, mock_clamav, mock_yara, make_request, make_attachment
    ):
        """ClamAV signe le fichier comme infecté → BLOCK."""
        mock_yara.enabled = True
        mock_yara.scan_bytes = AsyncMock(return_value=YaraScanResult(matched=False))

        mock_clamav.enabled = True
        mock_clamav.scan_bytes = AsyncMock(return_value=ClamAVResult(
            infected=True, signature="Eicar-Test-Signature", status="FOUND",
        ))

        # file_type OTHER pour atteindre ClamAV (YARA ne matche pas ici) sans
        # court-circuiter sur l'heuristique.
        request = make_request(
            attachments=[make_attachment(file_type=FileType.OTHER, sha256="d" * 64)],
        )
        bytes_map = {"d" * 64: b"infected"}
        response = await orchestrator.analyze_with_bytes(request, bytes_map)

        assert response.overall_verdict == Verdict.BLOCK
        assert response.attachments[0].clamav_signature == "Eicar-Test-Signature"

    async def test_clean_bytes_returns_allow(
        self, orchestrator, mock_yara, mock_clamav, make_request, make_attachment
    ):
        """YARA, ClamAV, MISP rien → ALLOW pour fichier basique."""
        mock_yara.enabled = True
        mock_yara.scan_bytes = AsyncMock(return_value=YaraScanResult(matched=False))
        mock_clamav.enabled = True
        mock_clamav.scan_bytes = AsyncMock(return_value=ClamAVResult(infected=False))

        request = make_request(
            attachments=[make_attachment(file_type=FileType.PDF, sha256="e" * 64,
                                         filename="document.pdf")],
            sender="trust@hopital.fr",
        )
        bytes_map = {"e" * 64: b"%PDF-1.4\n%clean"}
        response = await orchestrator.analyze_with_bytes(request, bytes_map)

        assert response.overall_verdict == Verdict.ALLOW
