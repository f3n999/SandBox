"""
Fixtures pytest globales — partagées par les tests unitaires, intégration et E2E.
"""
from __future__ import annotations

import asyncio
import os
from datetime import datetime
from typing import AsyncIterator

import pytest
import pytest_asyncio

# Forcer un .env minimaliste pour les tests (avant import des settings)
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production-only-here-for-pytest")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test_db")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")
os.environ.setdefault("YARA_ENABLED", "false")
os.environ.setdefault("CLAMAV_ENABLED", "false")
os.environ.setdefault("SCHEDULE_ENABLED", "false")
os.environ.setdefault("API_KEY_PEPPER", "test-pepper")


@pytest.fixture(scope="session")
def event_loop():
    """Event loop unique pour toute la session de tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# ─────────────────────────────────────────────────────────────
#  Factory helpers — schemas Pydantic
# ─────────────────────────────────────────────────────────────

@pytest.fixture
def make_attachment():
    """Factory pour AttachmentMetadata."""
    from orchestrator.models.schemas import AttachmentMetadata, FileType

    def _f(
        filename: str = "test.pdf",
        sha256: str = "a" * 64,
        file_type: FileType = FileType.PDF,
        file_size: int = 50_000,
        is_encrypted: bool = False,
        is_macro_enabled: bool = False,
        mime_type: str | None = None,
    ) -> AttachmentMetadata:
        return AttachmentMetadata(
            filename=filename,
            sha256=sha256,
            file_type=file_type,
            file_size=file_size,
            is_encrypted=is_encrypted,
            is_macro_enabled=is_macro_enabled,
            mime_type=mime_type,
        )

    return _f


@pytest.fixture
def make_request(make_attachment):
    """Factory pour AnalysisRequest."""
    from orchestrator.models.schemas import AnalysisRequest, EmailMetadata

    def _f(
        attachments=None,
        sender: str = "user@example.com",
        spf: str = "pass",
        dkim: str = "pass",
        dmarc: str = "pass",
        recipient_count: int = 1,
    ) -> AnalysisRequest:
        if attachments is None:
            attachments = [make_attachment()]
        domain = sender.split("@")[1]
        return AnalysisRequest(
            agent_id="test-agent",
            hospital_id="test-hospital",
            email=EmailMetadata(
                message_id="<test@example.com>",
                sender=sender,
                sender_domain=domain,
                recipient_count=recipient_count,
                subject_hash="b" * 64,
                received_at=datetime.utcnow(),
                has_attachments=True,
                spf_result=spf,
                dkim_result=dkim,
                dmarc_result=dmarc,
            ),
            attachments=attachments,
        )

    return _f


# ─────────────────────────────────────────────────────────────
#  Mock services — pour tests d'intégration sans dépendances externes
# ─────────────────────────────────────────────────────────────

@pytest.fixture
def mock_cache():
    """CacheService mocké en mémoire (pas de Redis)."""
    from unittest.mock import AsyncMock

    cache = AsyncMock()
    storage = {}

    async def get_hash(sha):
        return storage.get(sha)

    async def set_hash(sha, verdict, **kwargs):
        storage[sha] = {
            "verdict": verdict.value if hasattr(verdict, "value") else verdict,
            "threat_name": kwargs.get("threat_name"),
            "confidence": kwargs.get("confidence", 0.0),
            "source": kwargs.get("source", "test"),
        }

    cache.get_hash_verdict.side_effect = get_hash
    cache.set_hash_verdict.side_effect = set_hash
    cache.set_task_verdict = AsyncMock()
    cache.update_sender_reputation = AsyncMock()
    cache.check_rate_limit = AsyncMock(return_value=True)
    cache.health_check = AsyncMock(return_value=True)
    # Verrou acquis par défaut (comportement "je suis seul") — les tests
    # qui veulent simuler une soumission CAPE concurrente le repassent à
    # AsyncMock(return_value=False) explicitement.
    cache.try_acquire_lock = AsyncMock(return_value=True)
    cache.renew_lock = AsyncMock()
    cache._storage = storage
    return cache


@pytest.fixture
def mock_misp():
    """MISP qui ne trouve rien par défaut."""
    from unittest.mock import AsyncMock

    misp = AsyncMock()
    misp.search_hash = AsyncMock(return_value={"found": False, "misp_score": 0.0})
    misp.search_domain = AsyncMock(return_value={"found": False})
    misp.health_check = AsyncMock(return_value=True)
    return misp


@pytest.fixture
def mock_cape():
    """CAPE mocké — retourne SUSPECT par défaut."""
    from unittest.mock import AsyncMock
    from orchestrator.models.schemas import Verdict

    cape = AsyncMock()
    cape.analyze_and_verdict = AsyncMock(return_value={
        "verdict": Verdict.SUSPECT, "cape_score": 0.5,
        "confidence": 0.5, "signatures_matched": [], "threat_name": None,
    })
    cape.health_check = AsyncMock(return_value=True)
    return cape


@pytest.fixture
def mock_yara():
    """YARA scanner désactivé."""
    from unittest.mock import AsyncMock, MagicMock
    from orchestrator.services.yara_scanner import YaraScanResult

    yara = MagicMock()
    yara.enabled = False
    yara.scan_bytes = AsyncMock(return_value=YaraScanResult(matched=False))
    yara.health_check = MagicMock(return_value=False)
    return yara


@pytest.fixture
def mock_clamav():
    """ClamAV désactivé."""
    from unittest.mock import AsyncMock, MagicMock
    from orchestrator.services.clamav_client import ClamAVResult

    cav = MagicMock()
    cav.enabled = False
    cav.scan_bytes = AsyncMock(return_value=ClamAVResult(infected=False, status="DISABLED"))
    cav.health_check = AsyncMock(return_value=False)
    return cav
