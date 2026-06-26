"""
Tests de la couche d'autorisation (scopes + bootstrap des clés API).

On teste les dépendances FastAPI directement (sans TestClient ni DB) en
injectant la clé / un faux service api_keys.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from orchestrator.api import main as api_main
from orchestrator.services.auth import AuthenticatedKey


def _key(*scopes: str) -> AuthenticatedKey:
    return AuthenticatedKey(id=1, name="k", scopes=list(scopes))


@pytest.mark.asyncio
class TestRequireScope:
    async def test_allows_matching_scope(self):
        dep = api_main.require_scope("upload")
        key = _key("upload")
        assert await dep(key=key) is key

    async def test_admin_is_superscope(self):
        """Une clé 'admin' passe n'importe quel scope."""
        dep = api_main.require_scope("upload")
        key = _key("admin")
        assert await dep(key=key) is key

    async def test_denies_missing_scope(self):
        """Une clé 'analyze' NE peut PAS faire une action 'admin'."""
        dep = api_main.require_scope("admin")
        with pytest.raises(HTTPException) as exc:
            await dep(key=_key("analyze"))
        assert exc.value.status_code == 403


class _FakeKeys:
    def __init__(self, any_exists: bool, verify_result=None):
        self._any_exists = any_exists
        self._verify_result = verify_result

    async def any_key_exists(self, db):
        return self._any_exists

    async def verify(self, db, plaintext):
        return self._verify_result


@pytest.mark.asyncio
class TestAuthorizeKeyCreation:
    async def test_bootstrap_allows_without_key(self, monkeypatch):
        """Aucune clé n'a jamais existé → création libre (bootstrap)."""
        monkeypatch.setattr(api_main.services, "api_keys", _FakeKeys(any_exists=False), raising=False)
        assert await api_main.authorize_key_creation(db=None, x_api_key=None) is None

    async def test_requires_key_when_keys_exist(self, monkeypatch):
        """Une clé existe déjà + pas de header → 401."""
        monkeypatch.setattr(api_main.services, "api_keys", _FakeKeys(any_exists=True), raising=False)
        with pytest.raises(HTTPException) as exc:
            await api_main.authorize_key_creation(db=None, x_api_key=None)
        assert exc.value.status_code == 401

    async def test_revoked_all_keys_does_not_reopen_bootstrap(self, monkeypatch):
        """Backdoor fermée : des clés ont existé (puis révoquées) → toujours
        admin requis, JAMAIS de réouverture du bootstrap non authentifié."""
        monkeypatch.setattr(api_main.services, "api_keys", _FakeKeys(any_exists=True), raising=False)
        with pytest.raises(HTTPException) as exc:
            await api_main.authorize_key_creation(db=None, x_api_key=None)
        assert exc.value.status_code == 401

    async def test_denies_non_admin_key(self, monkeypatch):
        """Clé valide mais sans scope admin → 403."""
        monkeypatch.setattr(
            api_main.services, "api_keys",
            _FakeKeys(any_exists=True, verify_result=_key("analyze")), raising=False,
        )
        with pytest.raises(HTTPException) as exc:
            await api_main.authorize_key_creation(db=None, x_api_key="mgx_x")
        assert exc.value.status_code == 403

    async def test_allows_admin_key(self, monkeypatch):
        """Clé admin valide → autorisé."""
        monkeypatch.setattr(
            api_main.services, "api_keys",
            _FakeKeys(any_exists=True, verify_result=_key("admin")), raising=False,
        )
        assert await api_main.authorize_key_creation(db=None, x_api_key="mgx_x") is None
