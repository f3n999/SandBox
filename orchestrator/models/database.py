"""
Modèles SQLAlchemy pour PostgreSQL.
Stockage des analyses, verdicts, et métriques.
"""
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, Text,
    Enum as SQLEnum, ForeignKey, Index, JSON
)
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.sql import func
from datetime import datetime
import enum

Base = declarative_base()


class VerdictEnum(str, enum.Enum):
    ALLOW = "allow"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    SUSPECT = "suspect"
    PENDING = "pending"
    ERROR = "error"
    TIMEOUT = "timeout"


class AnalysisTask(Base):
    """Tâche d'analyse principale."""
    __tablename__ = "analysis_tasks"

    id = Column(String(36), primary_key=True)
    agent_id = Column(String(100), nullable=False, index=True)
    hospital_id = Column(String(100), nullable=False, index=True)
    message_id = Column(String(255), nullable=False)
    sender = Column(String(255), nullable=False, index=True)
    sender_domain = Column(String(255), nullable=False, index=True)
    recipient_count = Column(Integer, default=1)
    overall_verdict = Column(
        SQLEnum(VerdictEnum), default=VerdictEnum.PENDING, index=True
    )
    stage = Column(String(50), default="received")
    risk_score = Column(Float, default=0.0)
    analysis_time_ms = Column(Integer, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), index=True)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    # Relations
    attachments = relationship("AttachmentAnalysis", back_populates="task", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_tasks_created_verdict", "created_at", "overall_verdict"),
        Index("ix_tasks_hospital_date", "hospital_id", "created_at"),
    )


class AttachmentAnalysis(Base):
    """Analyse d'une pièce jointe individuelle."""
    __tablename__ = "attachment_analyses"

    id = Column(Integer, primary_key=True, autoincrement=True)
    task_id = Column(String(36), ForeignKey("analysis_tasks.id"), nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    sha1 = Column(String(40), nullable=True)
    md5 = Column(String(32), nullable=True)
    filename = Column(String(255), nullable=False)
    file_size = Column(Integer, default=0)
    file_type = Column(String(20), default="other")
    mime_type = Column(String(100), nullable=True)
    is_encrypted = Column(Boolean, default=False)
    is_macro_enabled = Column(Boolean, default=False)

    verdict = Column(SQLEnum(VerdictEnum), default=VerdictEnum.PENDING)
    confidence = Column(Float, default=0.0)
    threat_name = Column(String(255), nullable=True)
    signatures_matched = Column(JSON, default=list)
    analysis_source = Column(String(50), default="pending")

    # Scores détaillés
    hash_score = Column(Float, default=0.0)
    heuristic_score = Column(Float, default=0.0)
    misp_score = Column(Float, default=0.0)
    cape_score = Column(Float, default=0.0)
    cape_task_id = Column(Integer, nullable=True)
    cape_report = Column(JSON, nullable=True)

    created_at = Column(DateTime, server_default=func.now())

    # Relations
    task = relationship("AnalysisTask", back_populates="attachments")

    __table_args__ = (
        Index("ix_attachment_sha256_verdict", "sha256", "verdict"),
    )


class HashCache(Base):
    """Cache de hash connus (malveillants ou sains)."""
    __tablename__ = "hash_cache"

    sha256 = Column(String(64), primary_key=True)
    verdict = Column(SQLEnum(VerdictEnum), nullable=False)
    threat_name = Column(String(255), nullable=True)
    source = Column(String(50), nullable=False)  # misp, cape, manual, virustotal
    confidence = Column(Float, default=0.0)
    first_seen = Column(DateTime, server_default=func.now())
    last_seen = Column(DateTime, server_default=func.now(), onupdate=func.now())
    hit_count = Column(Integer, default=1)


class SenderReputation(Base):
    """Réputation des expéditeurs basée sur l'historique."""
    __tablename__ = "sender_reputation"

    sender_domain = Column(String(255), primary_key=True)
    total_emails = Column(Integer, default=0)
    blocked_count = Column(Integer, default=0)
    allowed_count = Column(Integer, default=0)
    risk_ratio = Column(Float, default=0.0)
    is_whitelisted = Column(Boolean, default=False)
    is_blacklisted = Column(Boolean, default=False)
    last_updated = Column(DateTime, server_default=func.now(), onupdate=func.now())
