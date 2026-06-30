"""
Client Microsoft Graph API — mode app-only (Client Credentials).

Permissions requises (admin consent) :
  - Mail.Read                 (lecture des boîtes du tenant)
  - User.Read.All             (énumération des users)

Pas d'interaction utilisateur — l'application s'authentifie elle-même
avec son client_id + client_secret + tenant_id.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)


GRAPH_BASE = "https://graph.microsoft.com/v1.0"
LOGIN_BASE = "https://login.microsoftonline.com"


# ─────────────────────────────────────────────────────────────
#  Dataclasses pour les objets Graph
# ─────────────────────────────────────────────────────────────

@dataclass
class GraphUser:
    id: str
    user_principal_name: str
    display_name: Optional[str] = None
    mail: Optional[str] = None


@dataclass
class GraphAttachment:
    """Pièce jointe — métadonnées + contenu si téléchargé."""
    id: str
    name: str
    content_type: Optional[str]
    size: int
    is_inline: bool = False
    content_bytes: Optional[bytes] = None     # rempli par download_attachment()

    @property
    def sha256(self) -> Optional[str]:
        if self.content_bytes is None:
            return None
        return hashlib.sha256(self.content_bytes).hexdigest()


@dataclass
class GraphMessage:
    """Message email avec headers d'authentification extraits."""
    id: str
    subject: str
    received_at: datetime
    sender_address: str
    sender_name: Optional[str]
    reply_to: Optional[str]
    recipient_count: int
    has_attachments: bool
    body_preview: str
    spf_result: Optional[str] = None
    dkim_result: Optional[str] = None
    dmarc_result: Optional[str] = None
    attachments: list[GraphAttachment] = field(default_factory=list)

    @property
    def sender_domain(self) -> str:
        if "@" in self.sender_address:
            return self.sender_address.split("@", 1)[1].lower()
        return ""


# ─────────────────────────────────────────────────────────────
#  Auth + low-level HTTP
# ─────────────────────────────────────────────────────────────

class GraphAuth:
    """Gère le token OAuth2 Client Credentials (auto-refresh)."""

    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self._token: Optional[str] = None
        self._expires_at: float = 0
        self._lock = asyncio.Lock()

    async def get_token(self) -> str:
        """Récupère un token valide (refresh si expiré ou proche d'expirer)."""
        async with self._lock:
            now = asyncio.get_event_loop().time()
            if self._token and now < self._expires_at - 60:
                return self._token

            url = f"{LOGIN_BASE}/{self.tenant_id}/oauth2/v2.0/token"
            payload = {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": "https://graph.microsoft.com/.default",
            }
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(url, data=payload)
                response.raise_for_status()
                data = response.json()

            self._token = data["access_token"]
            self._expires_at = now + int(data.get("expires_in", 3600))
            logger.info("Graph token rafraîchi (expire dans %ss)", data.get("expires_in"))
            return self._token


# ─────────────────────────────────────────────────────────────
#  Client principal
# ─────────────────────────────────────────────────────────────

class GraphClient:
    """Client Microsoft Graph — opérations métier."""

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        request_timeout: int = 30,
    ):
        self.tenant_id = tenant_id
        self.auth = GraphAuth(tenant_id, client_id, client_secret)
        self.request_timeout = request_timeout

    async def _headers(self) -> dict[str, str]:
        token = await self.auth.get_token()
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

    async def _get(self, path: str, params: Optional[dict] = None) -> dict:
        url = path if path.startswith("http") else f"{GRAPH_BASE}{path}"
        headers = await self._headers()
        async with httpx.AsyncClient(timeout=self.request_timeout) as client:
            response = await client.get(url, headers=headers, params=params)
            if response.status_code == 401:
                # Token peut être expiré — refresh forcé + retry
                self.auth._token = None
                headers = await self._headers()
                response = await client.get(url, headers=headers, params=params)
            response.raise_for_status()
            return response.json()

    # ────────── Users ──────────

    async def list_users(
        self, top: int = 100, include_disabled: bool = False
    ) -> list[GraphUser]:
        """Liste les users du tenant (paginée automatiquement)."""
        params = {
            "$top": str(min(top, 999)),
            "$select": "id,displayName,mail,userPrincipalName,accountEnabled",
        }
        users: list[GraphUser] = []
        path: Optional[str] = "/users"

        while path and len(users) < top:
            data = await self._get(path, params=params if path == "/users" else None)
            for u in data.get("value", []):
                if not include_disabled and u.get("accountEnabled") is False:
                    continue
                users.append(GraphUser(
                    id=u["id"],
                    user_principal_name=u.get("userPrincipalName", ""),
                    display_name=u.get("displayName"),
                    mail=u.get("mail"),
                ))
                if len(users) >= top:
                    break
            path = data.get("@odata.nextLink")

        logger.info("Graph : %d user(s) récupéré(s)", len(users))
        return users

    # ────────── Messages ──────────

    async def list_user_messages(
        self,
        user_id: str,
        top: int = 25,
        since: Optional[datetime] = None,
        only_with_attachments: bool = True,
    ) -> list[GraphMessage]:
        """
        Récupère les messages d'une boîte.

        :param since: filtre `receivedDateTime ge <iso>` (scan différentiel)
        :param only_with_attachments: ne récupère que les emails avec PJ
        """
        select = ",".join([
            "id", "subject", "receivedDateTime", "from", "replyTo",
            "toRecipients", "ccRecipients", "internetMessageHeaders",
            "hasAttachments", "bodyPreview",
        ])
        params = {
            "$top": str(min(top, 999)),
            "$select": select,
        }

        filters = []
        if only_with_attachments:
            filters.append("hasAttachments eq true")
        if since:
            iso = since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            filters.append(f"receivedDateTime ge {iso}")
        if filters:
            params["$filter"] = " and ".join(filters)

        try:
            data = await self._get(f"/users/{user_id}/messages", params=params)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (404, 400):
                logger.warning("Boîte non disponible pour %s (licence Exchange pas encore provisionnée ?)", user_id)
                return []
            if exc.response.status_code in (401, 403):
                logger.error(
                    "Accès refusé pour %s — vérifier permissions Graph (Mail.Read)", user_id
                )
                return []
            raise

        messages = [self._parse_message(m) for m in data.get("value", [])]
        logger.info("  %d message(s) pour %s", len(messages), user_id)
        return messages

    def _parse_message(self, raw: dict) -> GraphMessage:
        """Convertit la réponse Graph en GraphMessage."""
        sender_addr = ""
        sender_name = None
        if raw.get("from"):
            ea = raw["from"].get("emailAddress", {})
            sender_addr = (ea.get("address") or "").lower()
            sender_name = ea.get("name")

        reply_to = None
        for r in raw.get("replyTo") or []:
            ea = r.get("emailAddress", {})
            if ea.get("address"):
                reply_to = ea["address"].lower()
                break

        recipient_count = len(raw.get("toRecipients") or []) + len(raw.get("ccRecipients") or [])
        received_str = raw.get("receivedDateTime", "")
        received_at = (
            datetime.fromisoformat(received_str.replace("Z", "+00:00"))
            if received_str else datetime.now(timezone.utc)
        )

        spf, dkim, dmarc = _extract_auth_headers(raw.get("internetMessageHeaders") or [])

        return GraphMessage(
            id=raw["id"],
            subject=raw.get("subject", "") or "",
            received_at=received_at,
            sender_address=sender_addr,
            sender_name=sender_name,
            reply_to=reply_to,
            recipient_count=max(recipient_count, 1),
            has_attachments=bool(raw.get("hasAttachments")),
            body_preview=raw.get("bodyPreview", "") or "",
            spf_result=spf,
            dkim_result=dkim,
            dmarc_result=dmarc,
        )

    # ────────── Actions ──────────

    async def move_to_junk(self, user_id: str, message_id: str) -> bool:
        """
        Déplace un message vers le dossier Junk Email de l'utilisateur.
        Requiert Mail.ReadWrite (application permission + admin consent).
        """
        try:
            headers = await self._headers()
            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.post(
                    f"{GRAPH_BASE}/users/{user_id}/messages/{message_id}/move",
                    json={"destinationId": "junkemail"},
                    headers=headers,
                )
            if response.status_code == 201:
                logger.info("Message %s déplacé vers Junk pour %s", message_id[:20], user_id)
                return True
            logger.warning(
                "move_to_junk échoué pour %s: HTTP %d — %s",
                user_id, response.status_code, response.text[:200],
            )
            return False
        except Exception as exc:
            logger.error("move_to_junk exception: %s", exc)
            return False

    # ────────── Attachments ──────────

    async def list_attachments(
        self, user_id: str, message_id: str, include_inline: bool = False
    ) -> list[GraphAttachment]:
        """Liste les pièces jointes d'un message (métadonnées seulement)."""
        try:
            data = await self._get(
                f"/users/{user_id}/messages/{message_id}/attachments",
                params={"$select": "id,name,contentType,size,isInline"},
            )
        except httpx.HTTPStatusError as exc:
            logger.warning("Impossible de lister les PJ de %s : %s", message_id, exc)
            return []

        attachments = []
        for a in data.get("value", []):
            if not include_inline and a.get("isInline"):
                continue
            attachments.append(GraphAttachment(
                id=a["id"],
                name=a.get("name", "unknown") or "unknown",
                content_type=a.get("contentType"),
                size=int(a.get("size", 0)),
                is_inline=bool(a.get("isInline", False)),
            ))
        return attachments

    async def download_attachment(
        self, user_id: str, message_id: str, attachment_id: str, max_size: int = 50 * 1024 * 1024
    ) -> Optional[bytes]:
        """
        Télécharge le contenu d'une pièce jointe.

        Utilise `/$value` qui retourne directement le binaire — sinon Graph
        renvoie un JSON avec contentBytes en base64 (FileAttachment uniquement).
        """
        headers = await self._headers()
        url = f"{GRAPH_BASE}/users/{user_id}/messages/{message_id}/attachments/{attachment_id}"

        async with httpx.AsyncClient(timeout=120) as client:
            # 1) Essayer l'endpoint $value (binaire direct)
            r = await client.get(url + "/$value", headers=headers)
            if r.status_code == 200:
                data = r.content
                if len(data) > max_size:
                    logger.warning("PJ %s ignorée (trop volumineuse : %d)", attachment_id, len(data))
                    return None
                return data

            # 2) Fallback : JSON avec contentBytes en base64
            r = await client.get(url, headers=headers)
            if r.status_code != 200:
                logger.warning("Téléchargement PJ %s échoué : HTTP %d", attachment_id, r.status_code)
                return None
            j = r.json()
            b64 = j.get("contentBytes")
            if not b64:
                return None
            try:
                data = base64.b64decode(b64)
                if len(data) > max_size:
                    return None
                return data
            except Exception as exc:
                logger.error("Décodage base64 échoué pour %s : %s", attachment_id, exc)
                return None


# ─────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────

def _extract_auth_headers(headers: list[dict]) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Extrait SPF / DKIM / DMARC depuis Authentication-Results."""
    spf = dkim = dmarc = None
    for h in headers:
        name = (h.get("name") or "").lower()
        value = (h.get("value") or "").lower()
        if name != "authentication-results":
            continue
        for token, target in (("spf=", "spf"), ("dkim=", "dkim"), ("dmarc=", "dmarc")):
            idx = value.find(token)
            if idx >= 0:
                rest = value[idx + len(token):]
                verdict = rest.split()[0].strip(";")
                if target == "spf":
                    spf = verdict
                elif target == "dkim":
                    dkim = verdict
                else:
                    dmarc = verdict
    return spf, dkim, dmarc
