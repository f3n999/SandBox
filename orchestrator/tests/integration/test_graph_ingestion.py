"""
Tests d'intégration de l'ingestion Graph API — Graph mocké.
"""
from __future__ import annotations

import contextlib
import hashlib
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from orchestrator.core.heuristics import HeuristicEngine
from orchestrator.ingestion import graph_ingestor as gi
from orchestrator.ingestion.graph_client import GraphAttachment, GraphMessage, GraphUser
from orchestrator.ingestion.graph_ingestor import (
    GraphIngestor, _build_analysis_request, _build_attachment_metadata,
)
from orchestrator.models.database import (
    AttachmentVerdict as AttachmentVerdictRow,
    EmailAnalysis as EmailAnalysisRow,
)
from orchestrator.models.schemas import Verdict
from orchestrator.services.orchestrator import OrchestratorService


class _CaptureSession:
    """Faux session DB qui capture `add()`/`execute()` au lieu d'écrire."""

    def __init__(self) -> None:
        self.added: list = []
        self.executed: list = []

    def add(self, obj) -> None:
        self.added.append(obj)

    async def execute(self, stmt):
        self.executed.append(stmt)
        return None


@pytest.fixture(autouse=True)
def _noop_persistence(monkeypatch):
    """Par défaut, la persistance est neutralisée (pas de vraie DB en test)."""

    @contextlib.asynccontextmanager
    async def _noop():
        yield _CaptureSession()

    monkeypatch.setattr(gi, "session_scope", lambda: _noop())


@pytest.fixture
def capture_persistence(monkeypatch):
    """Patche session_scope pour capturer les lignes persistées."""
    cap = _CaptureSession()

    @contextlib.asynccontextmanager
    async def _scope():
        yield cap

    monkeypatch.setattr(gi, "session_scope", lambda: _scope())
    return cap


@pytest.fixture
def orchestrator(mock_cache, mock_misp, mock_cape, mock_yara, mock_clamav):
    return OrchestratorService(
        cache=mock_cache, heuristic=HeuristicEngine(),
        misp=mock_misp, cape=mock_cape,
        yara=mock_yara, clamav=mock_clamav,
    )


def test_build_attachment_metadata_computes_sha256():
    content = b"some attachment content"
    att = GraphAttachment(
        id="att1", name="test.pdf", content_type="application/pdf",
        size=len(content), content_bytes=content,
    )
    meta = _build_attachment_metadata(att, content)
    assert meta.sha256 == hashlib.sha256(content).hexdigest()
    assert meta.file_size == len(content)
    assert meta.filename == "test.pdf"


def test_build_analysis_request_maps_correctly():
    msg = GraphMessage(
        id="msg1",
        subject="Test subject",
        received_at=datetime.now(timezone.utc),
        sender_address="user@example.com",
        sender_name="User",
        reply_to=None,
        recipient_count=2,
        has_attachments=True,
        body_preview="",
        spf_result="pass",
        dkim_result="pass",
        dmarc_result="pass",
    )
    from orchestrator.models.schemas import AttachmentMetadata, FileType
    att = AttachmentMetadata(
        filename="x.pdf", file_size=100, sha256="a" * 64, file_type=FileType.PDF,
    )
    request = _build_analysis_request(msg, [att], "tenant-1", "user@example.com")
    assert request.email.sender == "user@example.com"
    assert request.email.sender_domain == "example.com"
    assert request.email.recipient_count == 2
    assert len(request.attachments) == 1


@pytest.mark.asyncio
class TestGraphIngestor:
    async def test_scan_user_inbox_no_messages(self, orchestrator):
        graph = AsyncMock()
        graph.list_user_messages = AsyncMock(return_value=[])
        ingestor = GraphIngestor(graph, orchestrator, tenant_id="t1")

        user = GraphUser(id="u1", user_principal_name="u1@t.com", display_name="U1")
        responses = await ingestor.scan_user_inbox(user)
        assert responses == []

    async def test_scan_user_inbox_with_message_and_attachment(self, orchestrator):
        msg = GraphMessage(
            id="m1", subject="Hello", received_at=datetime.now(timezone.utc),
            sender_address="ok@hopital.fr", sender_name="OK",
            reply_to=None, recipient_count=1, has_attachments=True,
            body_preview="", spf_result="pass", dkim_result="pass", dmarc_result="pass",
        )
        att = GraphAttachment(
            id="a1", name="doc.pdf", content_type="application/pdf", size=1024,
        )
        content = b"%PDF-1.4 fake pdf bytes"

        graph = AsyncMock()
        graph.list_user_messages = AsyncMock(return_value=[msg])
        graph.list_attachments = AsyncMock(return_value=[att])
        graph.download_attachment = AsyncMock(return_value=content)

        ingestor = GraphIngestor(graph, orchestrator, tenant_id="t1")
        user = GraphUser(id="u1", user_principal_name="user@t.com", display_name="User")

        responses = await ingestor.scan_user_inbox(user)
        assert len(responses) == 1
        # Verdict probable : ALLOW (PDF normal, SPF pass)
        assert responses[0].overall_verdict in (Verdict.ALLOW, Verdict.REQUEST_DEEP_ANALYSIS)

    async def test_scan_message_persists_email_and_attachment(
        self, orchestrator, capture_persistence
    ):
        """Le fix critique : chaque analyse écrit 1 EmailAnalysis + N AttachmentVerdict."""
        msg = GraphMessage(
            id="m-persist", subject="Facture urgente",
            received_at=datetime.now(timezone.utc),
            sender_address="invoice-payment@evil.ru", sender_name="Evil",
            reply_to="attacker@gmail.com", recipient_count=3, has_attachments=True,
            body_preview="", spf_result="fail", dkim_result="fail", dmarc_result="fail",
        )
        att = GraphAttachment(
            id="a1", name="facture.exe", content_type="application/x-dosexec", size=5000,
        )
        content = b"MZ\x90\x00 fake executable payload"

        graph = AsyncMock()
        graph.list_user_messages = AsyncMock(return_value=[msg])
        graph.list_attachments = AsyncMock(return_value=[att])
        graph.download_attachment = AsyncMock(return_value=content)

        ingestor = GraphIngestor(graph, orchestrator, tenant_id="tenant-xyz")
        user = GraphUser(id="u1", user_principal_name="victim@hopital.fr", display_name="Victim")

        await ingestor.scan_user_inbox(user, session_id="sess-123")

        emails = [o for o in capture_persistence.added if isinstance(o, EmailAnalysisRow)]
        verdicts = [o for o in capture_persistence.added if isinstance(o, AttachmentVerdictRow)]

        assert len(emails) == 1, "exactement une EmailAnalysis doit être écrite"
        assert len(verdicts) == 1, "exactement une AttachmentVerdict doit être écrite"

        email = emails[0]
        assert email.session_id == "sess-123"
        assert email.tenant_id == "tenant-xyz"
        assert email.mailbox_user == "victim@hopital.fr"
        assert email.sender_domain == "evil.ru"
        assert email.reply_to == "attacker@gmail.com"   # Reply-To désormais persisté
        assert email.overall_verdict == Verdict.BLOCK.value  # .exe → heuristique BLOCK

        v = verdicts[0]
        assert v.email_id == email.id
        assert v.sha256 == hashlib.sha256(content).hexdigest()
        assert v.filename == "facture.exe"
        assert v.file_type == "exe"
        assert v.verdict == Verdict.BLOCK.value

        # Idempotence : id déterministe (tenant + message) + DELETE de dédup
        # AVANT l'insert → un ré-scan chevauchant ne duplique pas la ligne.
        import uuid as _uuid
        expected_id = _uuid.uuid5(_uuid.NAMESPACE_URL, "mgx|tenant-xyz|m-persist")
        assert email.id == str(expected_id)
        assert len(capture_persistence.executed) == 1  # le DELETE de déduplication
