"""
Modèles de données pour l'orchestrateur.
Validation stricte des entrées/sorties à chaque étape du pipeline.
"""
from pydantic import BaseModel, Field, field_validator
from typing import Optional
from enum import Enum
from datetime import datetime
import re


# ──────────────────── Enums ────────────────────

class Verdict(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    SUSPECT = "suspect"
    REQUEST_DEEP_ANALYSIS = "request_deep_analysis"
    PENDING = "pending"
    ERROR = "error"
    TIMEOUT = "timeout"


class AnalysisStage(str, Enum):
    RECEIVED = "received"
    HASH_LOOKUP = "hash_lookup"
    HEURISTIC = "heuristic"
    MISP_LOOKUP = "misp_lookup"
    CAPE_SUBMITTED = "cape_submitted"
    CAPE_ANALYZING = "cape_analyzing"
    CAPE_COMPLETED = "cape_completed"
    VERDICT_READY = "verdict_ready"
    FAILED = "failed"


class FileType(str, Enum):
    EXE = "exe"
    DLL = "dll"
    DOC = "doc"
    DOCX = "docx"
    DOCM = "docm"
    XLS = "xls"
    XLSX = "xlsx"
    XLSM = "xlsm"
    PDF = "pdf"
    ZIP = "zip"
    RAR = "rar"
    SEVEN_Z = "7z"
    JS = "js"
    VBS = "vbs"
    PS1 = "ps1"
    BAT = "bat"
    LNK = "lnk"
    ISO = "iso"
    IMG = "img"
    HTA = "hta"
    OTHER = "other"


# ──────────────────── Requêtes Agent → Backend ────────────────────

class EmailMetadata(BaseModel):
    """Métadonnées email envoyées par l'agent. Zéro donnée patient."""
    message_id: str = Field(..., description="ID unique du message email")
    sender: str = Field(..., description="Adresse email expéditeur")
    sender_domain: str = Field(..., description="Domaine expéditeur")
    recipient_count: int = Field(ge=1, description="Nombre de destinataires")
    subject_hash: str = Field(..., description="Hash du sujet (pas le sujet lui-même)")
    received_at: datetime
    has_attachments: bool
    spf_result: Optional[str] = None
    dkim_result: Optional[str] = None
    dmarc_result: Optional[str] = None

    @field_validator("sender")
    @classmethod
    def validate_email(cls, v: str) -> str:
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, v):
            raise ValueError(f"Adresse email invalide: {v}")
        return v.lower()


class AttachmentMetadata(BaseModel):
    """Métadonnées d'une pièce jointe. Hash uniquement, pas le contenu."""
    filename: str
    file_size: int = Field(ge=0, le=50 * 1024 * 1024)
    sha256: str = Field(..., min_length=64, max_length=64)
    sha1: Optional[str] = Field(None, min_length=40, max_length=40)
    md5: Optional[str] = Field(None, min_length=32, max_length=32)
    mime_type: Optional[str] = None
    file_type: FileType = FileType.OTHER
    is_encrypted: bool = False
    is_macro_enabled: bool = False

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, v: str) -> str:
        if not re.match(r"^[a-fA-F0-9]{64}$", v):
            raise ValueError("SHA256 invalide")
        return v.lower()


class AnalysisRequest(BaseModel):
    """Requête d'analyse complète depuis l'agent."""
    agent_id: str = Field(..., description="ID unique de l'agent")
    hospital_id: str = Field(..., description="ID de l'établissement")
    email: EmailMetadata
    attachments: list[AttachmentMetadata] = Field(..., min_length=1)
    request_deep_analysis: bool = False


# ──────────────────── Réponses Backend → Agent ────────────────────

class AttachmentVerdict(BaseModel):
    """Verdict pour une pièce jointe individuelle."""
    sha256: str
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    threat_name: Optional[str] = None
    signatures_matched: list[str] = []
    analysis_source: str = "unknown"  # cache, misp, heuristic, cape


class AnalysisResponse(BaseModel):
    """Réponse complète à l'agent."""
    task_id: str
    overall_verdict: Verdict
    stage: AnalysisStage
    attachments: list[AttachmentVerdict] = []
    requires_file_upload: bool = False
    message: str = ""
    analysis_time_ms: Optional[int] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ──────────────────── Upload fichier (chemin profond) ────────────────────

class FileUploadRequest(BaseModel):
    """Requête d'upload de fichier pour analyse CAPE."""
    task_id: str
    sha256: str
    agent_id: str


# ──────────────────── Scoring interne ────────────────────

class RiskScore(BaseModel):
    """Score de risque composé."""
    total: float = Field(ge=0.0, le=1.0)
    hash_score: float = 0.0       # Connu comme malveillant ?
    heuristic_score: float = 0.0  # Caractéristiques suspectes ?
    misp_score: float = 0.0       # IOC trouvé dans MISP ?
    cape_score: float = 0.0       # Score sandbox
    sender_score: float = 0.0     # Réputation expéditeur
    breakdown: dict = {}

    def compute_total(self) -> float:
        """Calcul pondéré du score total."""
        weights = {
            "hash": 0.35,
            "heuristic": 0.20,
            "misp": 0.25,
            "cape": 0.15,
            "sender": 0.05,
        }
        self.total = min(1.0, (
            self.hash_score * weights["hash"]
            + self.heuristic_score * weights["heuristic"]
            + self.misp_score * weights["misp"]
            + self.cape_score * weights["cape"]
            + self.sender_score * weights["sender"]
        ))
        return self.total


# ──────────────────── Stats / Dashboard ────────────────────

class DashboardStats(BaseModel):
    """Statistiques pour le dashboard SOC."""
    total_analyzed: int = 0
    total_blocked: int = 0
    total_allowed: int = 0
    total_quarantined: int = 0
    total_pending: int = 0
    false_positive_rate: float = 0.0
    avg_analysis_time_ms: float = 0.0
    top_threats: list[dict] = []
    top_blocked_senders: list[dict] = []
    period_start: Optional[datetime] = None
    period_end: Optional[datetime] = None
