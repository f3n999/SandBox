"""
Pré-filtrage par type de fichier pour le gating CAPE.

Objectif : réduire le volume envoyé au sandbox sans perdre en précision.
- `is_detonable()`     : seuls les fichiers à contenu actif valent une détonation.
- `static_type_score()`: score statique grossier basé sur le type (avant détonation).
- `compute_imphash()`  : hash de la table d'imports d'un PE → identique pour les
                         variantes recompilées → permet une déduplication "floue".
"""
from __future__ import annotations

import os

try:  # pefile est optionnel : sans lui, la dédup floue est juste désactivée.
    import pefile
except ImportError:  # pragma: no cover
    pefile = None


# Types à "contenu actif" → seuls candidats légitimes à la détonation CAPE.
DETONABLE_EXT = {
    ".exe", ".dll", ".scr", ".com", ".js", ".jse", ".vbs", ".vbe",
    ".ps1", ".bat", ".cmd", ".hta", ".wsf", ".lnk", ".iso", ".img",
    ".docm", ".xlsm", ".pptm", ".zip", ".rar", ".7z", ".cab", ".ace", ".jar",
    # .xls always detonable — XLM (Excel 4) macros are undetectable statically
    ".xls",
}
LEGACY_OFFICE = {".doc", ".xls", ".ppt"}
OOXML_OFFICE = {".docx", ".xlsx", ".pptx"}
HIGH_RISK_EXT = {
    ".exe", ".dll", ".scr", ".com", ".hta", ".lnk", ".ps1", ".js", ".vbs",
}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".iso", ".img", ".cab", ".jar", ".ace"}


def has_macro(content: bytes | None) -> bool:
    """Détection légère de macro VBA (conteneur OLE/CFB ou OOXML)."""
    if not content:
        return False
    if content[:8] == b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1":  # OLE / CFB
        low = content.lower()
        return b"_vba_project" in low or b"vba" in low or b"macros" in low
    # OOXML (.docx/.xlsx = zip) embarquant une macro
    return b"vbaproject.bin" in content.lower()


def is_detonable(filename: str, content: bytes | None = None) -> bool:
    """True si le fichier peut réellement s'exécuter → vaut une détonation CAPE.

    Un fichier sans contenu actif (PDF simple, image, .docx sans macro...) ne
    peut pas "exploser" : l'écarter du sandbox ne crée pas de faux négatif.
    """
    ext = os.path.splitext(filename or "")[1].lower()
    if ext in DETONABLE_EXT:
        return True
    if ext in (LEGACY_OFFICE | OOXML_OFFICE) and has_macro(content):
        return True
    return False


def static_type_score(filename: str, content: bytes | None = None) -> float:
    """Score statique [0,1] grossier basé sur le type, avant toute détonation."""
    ext = os.path.splitext(filename or "")[1].lower()
    if ext in HIGH_RISK_EXT:
        return 0.55
    if ext in (LEGACY_OFFICE | OOXML_OFFICE) and has_macro(content):
        return 0.50
    if ext in ARCHIVE_EXT:
        return 0.45
    return 0.20  # type peu risqué / inerte


def compute_imphash(content: bytes) -> str | None:
    """imphash d'un PE (None si pefile absent ou fichier non-PE)."""
    if pefile is None:
        return None
    try:
        pe = pefile.PE(data=content, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
        return pe.get_imphash() or None
    except Exception:  # noqa: BLE001 - fichier non-PE / corrompu → pas de dédup floue
        return None
