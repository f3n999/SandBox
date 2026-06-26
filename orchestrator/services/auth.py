"""
Authentification API key — bcrypt + persistance PostgreSQL.

Format d'une clé en clair :  mgx_<prefix>_<random>
- 3 lettres `mgx_`
- 8 chars de préfixe (lookup rapide)
- 48 chars de random urlsafe

Seul le hash bcrypt est stocké en DB. Le prefix est conservé en clair pour
identifier rapidement une clé compromise sans dump complet.
"""
from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import bcrypt
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from orchestrator.core.config import get_settings
from orchestrator.models.database import APIKey

logger = logging.getLogger(__name__)


KEY_PREFIX_TAG = "mgx_"
PREFIX_LEN = 8
RANDOM_LEN = 48


@dataclass
class IssuedKey:
    """Clé fraîchement émise — montrée UNE SEULE FOIS à l'utilisateur."""
    id: int
    name: str
    plaintext: str          # à transmettre au client (jamais redonné)
    prefix: str
    scopes: list[str]


@dataclass
class AuthenticatedKey:
    """Clé vérifiée — utilisée comme contexte d'autorisation."""
    id: int
    name: str
    scopes: list[str]


# ─────────────────────────────────────────────────────────────
#  Création / vérification
# ─────────────────────────────────────────────────────────────

def _generate_key() -> tuple[str, str]:
    """Génère (plaintext, prefix)."""
    prefix = secrets.token_urlsafe(PREFIX_LEN)[:PREFIX_LEN]
    random_part = secrets.token_urlsafe(RANDOM_LEN)[:RANDOM_LEN]
    plaintext = f"{KEY_PREFIX_TAG}{prefix}_{random_part}"
    return plaintext, prefix


def _pepper() -> bytes:
    """Pepper applicatif — concaténé avant bcrypt pour défense en profondeur."""
    pepper = get_settings().api_key_pepper or ""
    return pepper.encode("utf-8")


def _hash(plaintext: str) -> str:
    """Hash bcrypt (12 rounds par défaut)."""
    salted = plaintext.encode("utf-8") + _pepper()
    return bcrypt.hashpw(salted, bcrypt.gensalt(rounds=12)).decode("utf-8")


def _verify(plaintext: str, hashed: str) -> bool:
    salted = plaintext.encode("utf-8") + _pepper()
    try:
        return bcrypt.checkpw(salted, hashed.encode("utf-8"))
    except ValueError:
        return False


# ─────────────────────────────────────────────────────────────
#  Service principal
# ─────────────────────────────────────────────────────────────

class APIKeyService:
    """CRUD + vérification de clés API."""

    async def create(
        self,
        db: AsyncSession,
        name: str,
        scopes: Optional[list[str]] = None,
        expires_at: Optional[datetime] = None,
        notes: Optional[str] = None,
    ) -> IssuedKey:
        """Crée une nouvelle clé. Le plaintext n'est retourné qu'ici."""
        plaintext, prefix = _generate_key()
        hashed = _hash(plaintext)

        record = APIKey(
            name=name,
            key_hash=hashed,
            key_prefix=prefix,
            scopes=scopes or [],
            is_active=True,
            expires_at=expires_at,
            notes=notes,
        )
        db.add(record)
        await db.flush()
        logger.info("API key créée : id=%d name=%s prefix=%s", record.id, name, prefix)
        return IssuedKey(
            id=record.id, name=name, plaintext=plaintext,
            prefix=prefix, scopes=scopes or [],
        )

    async def verify(
        self, db: AsyncSession, plaintext: str
    ) -> Optional[AuthenticatedKey]:
        """Vérifie une clé fournie. Retourne None si invalide."""
        if not plaintext or not plaintext.startswith(KEY_PREFIX_TAG):
            return None

        # Extraire le prefix pour lookup rapide
        try:
            without_tag = plaintext[len(KEY_PREFIX_TAG):]
            prefix = without_tag.split("_", 1)[0][:PREFIX_LEN]
        except (IndexError, ValueError):
            return None
        if len(prefix) != PREFIX_LEN:
            return None

        now = datetime.now(timezone.utc)
        stmt = (
            select(APIKey)
            .where(APIKey.key_prefix == prefix)
            .where(APIKey.is_active.is_(True))
            .where(APIKey.revoked_at.is_(None))
        )
        result = await db.execute(stmt)
        candidates = result.scalars().all()

        for key in candidates:
            if key.expires_at and key.expires_at < now:
                continue
            if _verify(plaintext, key.key_hash):
                # Update last_used_at (best-effort, non-bloquant en cas d'erreur)
                try:
                    await db.execute(
                        update(APIKey)
                        .where(APIKey.id == key.id)
                        .values(last_used_at=now)
                    )
                except Exception:  # noqa: BLE001
                    pass
                return AuthenticatedKey(id=key.id, name=key.name, scopes=key.scopes)

        return None

    async def revoke(self, db: AsyncSession, key_id: int) -> bool:
        """Révoque une clé (irréversible)."""
        now = datetime.now(timezone.utc)
        stmt = (
            update(APIKey)
            .where(APIKey.id == key_id)
            .where(APIKey.revoked_at.is_(None))
            .values(is_active=False, revoked_at=now)
        )
        result = await db.execute(stmt)
        return result.rowcount > 0

    async def count_active(self, db: AsyncSession) -> int:
        """Nombre de clés actives — sert au bootstrap de la première clé."""
        stmt = (
            select(func.count())
            .select_from(APIKey)
            .where(APIKey.is_active.is_(True))
            .where(APIKey.revoked_at.is_(None))
        )
        result = await db.execute(stmt)
        return int(result.scalar() or 0)

    async def list_active(self, db: AsyncSession) -> list[dict]:
        stmt = (
            select(APIKey)
            .where(APIKey.is_active.is_(True))
            .where(APIKey.revoked_at.is_(None))
            .order_by(APIKey.created_at.desc())
        )
        result = await db.execute(stmt)
        return [
            {
                "id": k.id,
                "name": k.name,
                "prefix": k.key_prefix,
                "scopes": k.scopes,
                "created_at": k.created_at.isoformat(),
                "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
                "expires_at": k.expires_at.isoformat() if k.expires_at else None,
            }
            for k in result.scalars().all()
        ]
