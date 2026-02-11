"""
Moteur heuristique de scoring.
Évalue le risque d'un email/pièce jointe AVANT sandbox.
Première ligne de défense — rapide, sans I/O lourde.
"""
import logging
from orchestrator.models.schemas import (
    AnalysisRequest, AttachmentMetadata, RiskScore, FileType
)

logger = logging.getLogger(__name__)

# ──────────────────── Règles heuristiques ────────────────────

HIGH_RISK_EXTENSIONS: dict[FileType, float] = {
    FileType.EXE: 0.95, FileType.DLL: 0.90, FileType.JS: 0.85,
    FileType.VBS: 0.90, FileType.PS1: 0.88, FileType.BAT: 0.80,
    FileType.HTA: 0.92, FileType.LNK: 0.85, FileType.ISO: 0.80,
    FileType.IMG: 0.78,
}

MEDIUM_RISK_EXTENSIONS: dict[FileType, float] = {
    FileType.DOCM: 0.75, FileType.XLSM: 0.75,
    FileType.DOC: 0.40, FileType.XLS: 0.40,
}

LOW_RISK_EXTENSIONS: dict[FileType, float] = {
    FileType.PDF: 0.15, FileType.DOCX: 0.10, FileType.XLSX: 0.10,
}

SUSPICIOUS_SENDER_PATTERNS: list[str] = [
    "noreply-security", "urgent-notification", "account-verify",
    "invoice-payment", "document-share", "facture-impayee",
    "mise-a-jour-obligatoire", "confirmation-paiement",
]

HEALTH_SECTOR_SPOOFED_DOMAINS: list[str] = [
    "ameli.fr", "service-public.fr", "hopital", "sante.gouv",
    "has-sante", "ars.sante", "cnam.fr", "mssante.fr",
]


class HeuristicEngine:
    """Moteur de scoring heuristique pour triage rapide."""

    def score_attachment(self, attachment: AttachmentMetadata) -> dict:
        """Score une pièce jointe individuelle."""
        score = 0.0
        reasons = []

        # 1. Type de fichier
        if attachment.file_type in HIGH_RISK_EXTENSIONS:
            ext_score = HIGH_RISK_EXTENSIONS[attachment.file_type]
            score = max(score, ext_score)
            reasons.append(f"high_risk_ext:{attachment.file_type.value}={ext_score}")
        elif attachment.file_type in MEDIUM_RISK_EXTENSIONS:
            ext_score = MEDIUM_RISK_EXTENSIONS[attachment.file_type]
            score = max(score, ext_score)
            reasons.append(f"medium_risk_ext:{attachment.file_type.value}={ext_score}")
        elif attachment.file_type in LOW_RISK_EXTENSIONS:
            score = max(score, LOW_RISK_EXTENSIONS[attachment.file_type])
        else:
            score = 0.20
            reasons.append("unknown_extension")

        # 2. Fichier chiffré (archive protégée par mot de passe = drop pattern)
        if attachment.is_encrypted:
            score = min(1.0, score + 0.25)
            reasons.append("encrypted_archive")

        # 3. Macros activées
        if attachment.is_macro_enabled:
            score = min(1.0, score + 0.30)
            reasons.append("macro_enabled")

        # 4. Double extension (facture.pdf.exe)
        if self._has_double_extension(attachment.filename):
            score = min(1.0, score + 0.35)
            reasons.append("double_extension")

        # 5. Taille suspecte
        size_flag = self._score_file_size(attachment.file_size, attachment.file_type)
        if size_flag > 0:
            score = min(1.0, score + size_flag)
            reasons.append(f"suspicious_size:{size_flag:.2f}")

        # 6. MIME type mismatch
        if self._mime_mismatch(attachment):
            score = min(1.0, score + 0.30)
            reasons.append("mime_type_mismatch")

        return {"score": round(min(score, 1.0), 3), "reasons": reasons}

    def score_email_context(self, request: AnalysisRequest) -> dict:
        """Score le contexte email (expéditeur, auth, patterns)."""
        score = 0.0
        reasons = []
        email = request.email

        # 1. Échecs SPF/DKIM/DMARC
        auth_failures = 0
        for check, result in [
            ("spf", email.spf_result),
            ("dkim", email.dkim_result),
            ("dmarc", email.dmarc_result),
        ]:
            if result and result.lower() not in ("pass", "none", "neutral"):
                auth_failures += 1
                reasons.append(f"{check}_fail:{result}")

        if auth_failures >= 2:
            score += 0.40
            reasons.append("multiple_auth_failures")
        elif auth_failures == 1:
            score += 0.15

        # 2. Patterns expéditeur suspect
        sender_lower = email.sender.lower()
        for pattern in SUSPICIOUS_SENDER_PATTERNS:
            if pattern in sender_lower:
                score += 0.20
                reasons.append(f"suspicious_sender:{pattern}")
                break

        # 3. Usurpation domaine santé
        domain = email.sender_domain.lower()
        for spoofed in HEALTH_SECTOR_SPOOFED_DOMAINS:
            if spoofed in domain and auth_failures > 0:
                score += 0.35
                reasons.append(f"health_domain_spoofing:{spoofed}")
                break

        # 4. Envoi de masse
        if email.recipient_count > 50:
            score += 0.15
            reasons.append(f"mass_recipients:{email.recipient_count}")
        elif email.recipient_count > 20:
            score += 0.08

        return {"score": round(min(score, 1.0), 3), "reasons": reasons}

    def compute_risk(self, request: AnalysisRequest) -> RiskScore:
        """Calcule le score de risque global pour une requête d'analyse."""
        email_ctx = self.score_email_context(request)

        # Score max parmi toutes les PJ
        max_attachment_score = 0.0
        all_reasons = list(email_ctx["reasons"])
        for att in request.attachments:
            att_result = self.score_attachment(att)
            max_attachment_score = max(max_attachment_score, att_result["score"])
            all_reasons.extend(att_result["reasons"])

        risk = RiskScore(
            heuristic_score=max_attachment_score,
            sender_score=email_ctx["score"],
            breakdown={
                "attachment_score": max_attachment_score,
                "email_context_score": email_ctx["score"],
                "reasons": all_reasons,
            },
        )
        risk.compute_total()

        logger.info(
            f"Heuristic score: {risk.total:.3f} "
            f"(attachment={max_attachment_score:.3f}, email={email_ctx['score']:.3f})"
        )
        return risk

    # ──────────────────── Helpers privés ────────────────────

    @staticmethod
    def _has_double_extension(filename: str) -> bool:
        """Détecte les doubles extensions (facture.pdf.exe)."""
        dangerous = {".exe", ".dll", ".js", ".vbs", ".ps1", ".bat", ".hta", ".lnk", ".scr", ".cmd"}
        parts = filename.rsplit(".", maxsplit=2)
        if len(parts) >= 3:
            last_ext = f".{parts[-1].lower()}"
            if last_ext in dangerous:
                return True
        return False

    @staticmethod
    def _score_file_size(size: int, file_type: FileType) -> float:
        """
        Taille suspecte pour le type de fichier.
        Ex: un .exe de 15KB est suspect (dropper), un .pdf de 200B aussi.
        """
        if file_type in (FileType.EXE, FileType.DLL):
            if size < 20_000:  # < 20KB = possible dropper/stager
                return 0.15
            if size > 30_000_000:  # > 30MB = packing suspect
                return 0.10
        elif file_type in (FileType.PDF, FileType.DOC, FileType.DOCX):
            if size < 500:  # Quasi vide = leurre
                return 0.20
        elif file_type in (FileType.ZIP, FileType.RAR, FileType.SEVEN_Z):
            if size < 1000:  # Archive minuscule
                return 0.15
        return 0.0

    @staticmethod
    def _mime_mismatch(attachment: AttachmentMetadata) -> bool:
        """Détecte un mismatch extension/MIME type."""
        if not attachment.mime_type:
            return False
        mime = attachment.mime_type.lower()
        ft = attachment.file_type

        mismatches = {
            FileType.PDF: ["application/pdf"],
            FileType.DOCX: ["application/vnd.openxmlformats-officedocument"],
            FileType.XLSX: ["application/vnd.openxmlformats-officedocument"],
            FileType.EXE: ["application/x-dosexec", "application/x-executable", "application/x-msdownload"],
            FileType.ZIP: ["application/zip", "application/x-zip"],
        }
        expected_mimes = mismatches.get(ft)
        if expected_mimes:
            return not any(m in mime for m in expected_mimes)
        return False
