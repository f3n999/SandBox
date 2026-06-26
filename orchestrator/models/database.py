"""
Modèles SQLAlchemy 2.0 (async) — PostgreSQL.

Stockage long-terme :
- Sessions de scan (audit trail)
- Analyses d'emails et verdicts par pièce jointe
- Cache de hash (synchronisé avec Redis pour persistance)
- Réputation expéditeurs
- API keys (hash bcrypt)
- Rapports CAPE complets en JSONB (interrogeables)
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional, Any

from sqlalchemy import (
    String, Integer, Float, Boolean, DateTime, Text,
    ForeignKey, Index, BigInteger,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.sql import func


class Base(DeclarativeBase):
    """Base déclarative SQLAlchemy 2.0."""
    pass


# ─────────────────────────────────────────────────────────────
#  Sessions de scan (par batch, ex: un run du scheduler Graph)
# ─────────────────────────────────────────────────────────────

class ScanSession(Base):
    """Une exécution complète du scanner (manuel ou planifié)."""
    __tablename__ = "scan_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    source: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    # source: "graph_scheduled", "graph_manual", "api_agent", "api_upload"
    tenant_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    triggered_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    users_scanned: Mapped[int] = mapped_column(Integer, default=0)
    emails_scanned: Mapped[int] = mapped_column(Integer, default=0)
    attachments_scanned: Mapped[int] = mapped_column(Integer, default=0)
    block_count: Mapped[int] = mapped_column(Integer, default=0)
    quarantine_count: Mapped[int] = mapped_column(Integer, default=0)
    suspect_count: Mapped[int] = mapped_column(Integer, default=0)
    allow_count: Mapped[int] = mapped_column(Integer, default=0)
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    emails: Mapped[list["EmailAnalysis"]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )


# ─────────────────────────────────────────────────────────────
#  Analyses email (1 par message) + verdicts (1 par PJ)
# ─────────────────────────────────────────────────────────────

class EmailAnalysis(Base):
    """Analyse d'un email (peut contenir N pièces jointes).

    PK = uuid5 déterministe (tenant + message_id) côté ingestion : une
    ré-analyse du même email (scan différentiel chevauchant) remplace la ligne
    au lieu d'en créer une nouvelle.
    """
    __tablename__ = "email_analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    session_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("scan_sessions.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # Identité message (Graph API ou agent)
    message_id: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    tenant_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    mailbox_user: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    subject_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Expéditeur + auth email
    sender: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    sender_domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    reply_to: Mapped[Optional[str]] = mapped_column(String(320), nullable=True)
    spf_result: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    dkim_result: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    dmarc_result: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)

    # Métadonnées email
    recipient_count: Mapped[int] = mapped_column(Integer, default=1)
    has_attachments: Mapped[bool] = mapped_column(Boolean, default=False)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    # Verdict global
    overall_verdict: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    stage: Mapped[str] = mapped_column(String(32), default="received")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    analysis_time_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )

    # Relations
    session: Mapped[Optional[ScanSession]] = relationship(back_populates="emails")
    attachments: Mapped[list["AttachmentVerdict"]] = relationship(
        back_populates="email", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_email_received_verdict", "received_at", "overall_verdict"),
        Index("ix_email_tenant_received", "tenant_id", "received_at"),
    )


class AttachmentVerdict(Base):
    """Verdict pour une pièce jointe d'un email."""
    __tablename__ = "attachment_verdicts"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    email_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("email_analyses.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    # Identification fichier
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    sha1: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    md5: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    file_size: Mapped[int] = mapped_column(BigInteger, default=0)
    file_type: Mapped[str] = mapped_column(String(16), default="other")
    mime_type: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    is_encrypted: Mapped[bool] = mapped_column(Boolean, default=False)
    is_macro_enabled: Mapped[bool] = mapped_column(Boolean, default=False)

    # Verdict + breakdown
    verdict: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    threat_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    analysis_source: Mapped[str] = mapped_column(String(32), default="pending")
    signatures_matched: Mapped[list[str]] = mapped_column(JSONB, default=list)

    # Scores par étape
    heuristic_score: Mapped[float] = mapped_column(Float, default=0.0)
    yara_matches: Mapped[list[str]] = mapped_column(JSONB, default=list)
    clamav_signature: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    misp_score: Mapped[float] = mapped_column(Float, default=0.0)
    misp_events: Mapped[list[dict]] = mapped_column(JSONB, default=list)
    cape_score: Mapped[float] = mapped_column(Float, default=0.0)
    cape_task_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    cape_report: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )

    email: Mapped[EmailAnalysis] = relationship(back_populates="attachments")

    __table_args__ = (
        Index("ix_attach_sha256_verdict", "sha256", "verdict"),
        Index("ix_attach_threat_name", "threat_name"),
        Index("ix_attach_cape_report_gin", "cape_report", postgresql_using="gin"),
    )


# ─────────────────────────────────────────────────────────────
#  Cache de hash (miroir long-terme du cache Redis)
# ─────────────────────────────────────────────────────────────

class HashCache(Base):
    """Hash connus (malveillants/sains) — persistance des verdicts validés."""
    __tablename__ = "hash_cache"

    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    threat_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    hit_count: Mapped[int] = mapped_column(Integer, default=1)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


# ─────────────────────────────────────────────────────────────
#  Réputation expéditeurs
# ─────────────────────────────────────────────────────────────

class SenderReputation(Base):
    __tablename__ = "sender_reputation"

    sender_domain: Mapped[str] = mapped_column(String(255), primary_key=True)
    total_emails: Mapped[int] = mapped_column(Integer, default=0)
    blocked_count: Mapped[int] = mapped_column(Integer, default=0)
    allowed_count: Mapped[int] = mapped_column(Integer, default=0)
    risk_ratio: Mapped[float] = mapped_column(Float, default=0.0)
    is_whitelisted: Mapped[bool] = mapped_column(Boolean, default=False)
    is_blacklisted: Mapped[bool] = mapped_column(Boolean, default=False)
    last_updated: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


# ─────────────────────────────────────────────────────────────
#  API keys (auth agents/intégrations)
# ─────────────────────────────────────────────────────────────

class APIKey(Base):
    """Clé d'authentification — stocke uniquement le hash bcrypt."""
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(8), nullable=False, index=True)
    # Pour identifier la clé rapidement sans révéler le secret
    scopes: Mapped[list[str]] = mapped_column(JSONB, default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
