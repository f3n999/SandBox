"""
Configuration centralisée via pydantic-settings.
Charge depuis .env, variables d'environnement, ou valeurs par défaut.
AUCUN secret en dur.
"""
from pydantic_settings import BaseSettings
from pydantic import Field, field_validator
from typing import Optional
from functools import lru_cache


class Settings(BaseSettings):
    """Configuration de l'orchestrateur."""

    # --- API ---
    app_name: str = "Ransomware Defense Orchestrator"
    app_version: str = "1.0.0"
    debug: bool = False
    log_level: str = "INFO"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    secret_key: str = Field(..., description="Clé secrète pour JWT/sessions")
    allowed_origins: list[str] = ["https://dashboard.defense-ransomware.local"]

    # --- Database ---
    database_url: str = Field(..., description="PostgreSQL connection string")

    # --- Redis ---
    redis_url: str = "redis://redis:6379/0"
    cache_ttl_known_hash: int = 86400      # 24h pour hash connu
    cache_ttl_verdict: int = 3600          # 1h pour verdicts

    # --- CAPE Sandbox ---
    cape_api_url: str = "http://cape:8000"
    cape_api_token: Optional[str] = None
    cape_timeout: int = 300                # 5 min max pour analyse
    cape_poll_interval: int = 10           # Poll toutes les 10s
    cape_max_file_size: int = 50 * 1024 * 1024  # 50MB

    # --- MISP ---
    misp_url: str = "http://misp:80"
    misp_api_key: Optional[str] = None
    misp_verify_ssl: bool = False

    # --- Scoring ---
    score_threshold_allow: float = 0.3     # En dessous = ALLOW
    score_threshold_suspect: float = 0.6   # Entre 0.3-0.6 = SUSPECT → CAPE
    score_threshold_block: float = 0.8     # Au dessus = BLOCK direct
    max_analysis_time: int = 600           # 10 min max total

    # --- Agent Auth ---
    agent_api_key_hash: Optional[str] = None  # Hash bcrypt de la clé API agent
    jwt_algorithm: str = "HS256"
    jwt_expiry_minutes: int = 60

    @field_validator("database_url")
    @classmethod
    def validate_db_url(cls, v: str) -> str:
        if "SecurePass123" in v or "password" in v.lower():
            raise ValueError(
                "ERREUR CRITIQUE: mot de passe par défaut détecté dans DATABASE_URL. "
                "Changez-le immédiatement."
            )
        return v

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
    }


@lru_cache()
def get_settings() -> Settings:
    """Singleton de configuration (cached)."""
    return Settings()
