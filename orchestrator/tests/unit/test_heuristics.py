"""
Tests unitaires pour le moteur heuristique.
Couvre les cas critiques : extensions dangereuses, double extensions,
macros, MIME mismatch, contexte email, scoring global.
"""
import pytest
from datetime import datetime

from orchestrator.core.heuristics import HeuristicEngine
from orchestrator.models.schemas import (
    AnalysisRequest, EmailMetadata, AttachmentMetadata, FileType,
)


@pytest.fixture
def engine():
    return HeuristicEngine()


def _make_attachment(
    filename="test.pdf",
    sha256="a" * 64,
    file_type=FileType.PDF,
    file_size=50000,
    is_encrypted=False,
    is_macro_enabled=False,
    mime_type=None,
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


def _make_request(
    attachments=None,
    sender="user@example.com",
    spf="pass", dkim="pass", dmarc="pass",
    recipient_count=1,
) -> AnalysisRequest:
    if attachments is None:
        attachments = [_make_attachment()]
    domain = sender.split("@")[1]
    return AnalysisRequest(
        agent_id="test-agent-01",
        hospital_id="hopital-test",
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


# ──────────────────── Tests Extension ────────────────────

class TestAttachmentScoring:
    def test_exe_is_high_risk(self, engine):
        att = _make_attachment(filename="malware.exe", file_type=FileType.EXE)
        result = engine.score_attachment(att)
        assert result["score"] >= 0.90

    def test_pdf_is_low_risk(self, engine):
        att = _make_attachment(filename="rapport.pdf", file_type=FileType.PDF)
        result = engine.score_attachment(att)
        assert result["score"] <= 0.20

    def test_docm_is_medium_risk(self, engine):
        att = _make_attachment(filename="facture.docm", file_type=FileType.DOCM)
        result = engine.score_attachment(att)
        assert 0.50 <= result["score"] <= 0.90

    def test_vbs_is_high_risk(self, engine):
        att = _make_attachment(filename="script.vbs", file_type=FileType.VBS)
        result = engine.score_attachment(att)
        assert result["score"] >= 0.85


# ──────────────────── Tests Double Extension ────────────────────

class TestDoubleExtension:
    def test_double_ext_detected(self, engine):
        att = _make_attachment(filename="facture.pdf.exe", file_type=FileType.EXE)
        result = engine.score_attachment(att)
        assert "double_extension" in str(result["reasons"])
        assert result["score"] >= 0.95

    def test_normal_ext_no_flag(self, engine):
        att = _make_attachment(filename="document.pdf", file_type=FileType.PDF)
        result = engine.score_attachment(att)
        assert "double_extension" not in str(result["reasons"])

    def test_triple_ext_detected(self, engine):
        att = _make_attachment(filename="readme.txt.pdf.scr", file_type=FileType.OTHER)
        result = engine.score_attachment(att)
        # .scr est dans les extensions dangereuses
        assert result["score"] > 0.3


# ──────────────────── Tests Macros & Encryption ────────────────────

class TestMacrosAndEncryption:
    def test_macro_enabled_increases_score(self, engine):
        no_macro = _make_attachment(file_type=FileType.DOC, is_macro_enabled=False)
        with_macro = _make_attachment(file_type=FileType.DOC, is_macro_enabled=True)
        s1 = engine.score_attachment(no_macro)["score"]
        s2 = engine.score_attachment(with_macro)["score"]
        assert s2 > s1

    def test_encrypted_archive_increases_score(self, engine):
        normal = _make_attachment(file_type=FileType.ZIP)
        encrypted = _make_attachment(file_type=FileType.ZIP, is_encrypted=True)
        s1 = engine.score_attachment(normal)["score"]
        s2 = engine.score_attachment(encrypted)["score"]
        assert s2 > s1


# ──────────────────── Tests MIME Mismatch ────────────────────

class TestMimeMismatch:
    def test_exe_with_pdf_mime_flagged(self, engine):
        att = _make_attachment(
            filename="virus.exe", file_type=FileType.EXE,
            mime_type="application/pdf",
        )
        result = engine.score_attachment(att)
        assert "mime_type_mismatch" in str(result["reasons"])

    def test_pdf_with_correct_mime_ok(self, engine):
        att = _make_attachment(
            filename="doc.pdf", file_type=FileType.PDF,
            mime_type="application/pdf",
        )
        result = engine.score_attachment(att)
        assert "mime_type_mismatch" not in str(result["reasons"])


# ──────────────────── Tests Contexte Email ────────────────────

class TestEmailContext:
    def test_auth_failures_increase_score(self, engine):
        req = _make_request(spf="fail", dkim="fail", dmarc="fail")
        result = engine.score_email_context(req)
        assert result["score"] >= 0.40

    def test_all_auth_pass_low_score(self, engine):
        req = _make_request(spf="pass", dkim="pass", dmarc="pass")
        result = engine.score_email_context(req)
        assert result["score"] <= 0.10

    def test_suspicious_sender_pattern(self, engine):
        req = _make_request(sender="urgent-notification@evil.com")
        result = engine.score_email_context(req)
        assert result["score"] > 0

    def test_health_domain_spoofing(self, engine):
        req = _make_request(
            sender="admin@fake-ameli.fr",
            spf="fail", dkim="fail",
        )
        result = engine.score_email_context(req)
        assert result["score"] >= 0.30

    def test_mass_recipients(self, engine):
        req = _make_request(recipient_count=100)
        result = engine.score_email_context(req)
        assert "mass_recipients" in str(result["reasons"])


# ──────────────────── Tests Pipeline Complet ────────────────────

class TestFullPipeline:
    def test_clean_email_low_score(self, engine):
        req = _make_request(
            attachments=[_make_attachment(file_type=FileType.PDF)],
            sender="collegue@hopital-paris.fr",
        )
        risk = engine.compute_risk(req)
        assert risk.total < 0.30

    def test_ransomware_pattern_high_score(self, engine):
        req = _make_request(
            attachments=[
                _make_attachment(
                    filename="facture.pdf.exe",
                    file_type=FileType.EXE,
                    is_encrypted=True,
                )
            ],
            sender="invoice-payment@suspicious.ru",
            spf="fail", dkim="fail",
        )
        risk = engine.compute_risk(req)
        assert risk.total > 0.60


# ──────────────────── Tests File Size ────────────────────

class TestFileSize:
    def test_tiny_exe_is_suspect(self, engine):
        att = _make_attachment(file_type=FileType.EXE, file_size=5000)
        result = engine.score_attachment(att)
        assert "suspicious_size" in str(result["reasons"])

    def test_empty_pdf_is_suspect(self, engine):
        att = _make_attachment(file_type=FileType.PDF, file_size=100)
        result = engine.score_attachment(att)
        assert "suspicious_size" in str(result["reasons"])
