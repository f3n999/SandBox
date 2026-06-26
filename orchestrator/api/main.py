"""
MailGuardianX Orchestrator — point d'entrée FastAPI.

Lifespan : initialise tous les services + démarre le scheduler si Azure configuré.
"""
from __future__ import annotations

import base64
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

from fastapi import (
    Depends, FastAPI, File, Form, Header, HTTPException, UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator
from sqlalchemy.ext.asyncio import AsyncSession

from orchestrator.core.config import get_settings
from orchestrator.core.heuristics import HeuristicEngine
from orchestrator.db.session import dispose_engine, get_session, init_engine
from orchestrator.ingestion.graph_client import GraphClient
from orchestrator.ingestion.scheduler import GraphScheduler
from orchestrator.models.schemas import (
    AnalysisRequest, AnalysisResponse, DashboardStats, Verdict,
)
from orchestrator.services.auth import APIKeyService, AuthenticatedKey
from orchestrator.services.cache import CacheService
from orchestrator.services.cape_client import CAPEClient
from orchestrator.services.clamav_client import ClamAVClient
from orchestrator.services.misp_client import MISPClient
from orchestrator.services.orchestrator import OrchestratorService
from orchestrator.services.stats import StatsService
from orchestrator.services.yara_scanner import YaraScanner

# ─────────────────────────────────────────────────────────────
#  Logging
# ─────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
#  Conteneur de services (initialisé dans lifespan)
# ─────────────────────────────────────────────────────────────

class ServiceContainer:
    settings = None
    cache: CacheService
    heuristic: HeuristicEngine
    yara: YaraScanner
    clamav: ClamAVClient
    misp: MISPClient
    cape: CAPEClient
    orchestrator: OrchestratorService
    stats: StatsService
    api_keys: APIKeyService
    scheduler: Optional[GraphScheduler] = None


services = ServiceContainer()


# ─────────────────────────────────────────────────────────────
#  Lifespan
# ─────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup : initialise tous les services + scheduler."""
    settings = get_settings()
    warnings = settings.validate_runtime()
    for w in warnings:
        logger.warning(w)
    services.settings = settings

    # DB engine
    init_engine()
    logger.info("✓ DB engine initialisé")

    # Redis cache
    services.cache = CacheService(redis_url=settings.redis_url)
    await services.cache.connect()
    logger.info("✓ Redis connecté")

    # Heuristique (pas d'init nécessaire)
    services.heuristic = HeuristicEngine()
    logger.info("✓ Heuristic engine prêt")

    # YARA
    services.yara = YaraScanner(
        rules_path=settings.yara.rules_path,
        enabled=settings.yara.enabled,
        timeout=settings.yara.timeout,
    )
    try:
        n = services.yara.load()
        logger.info("✓ YARA chargé (%d fichiers)", n)
    except Exception as exc:  # noqa: BLE001
        logger.error("YARA load failed : %s", exc)

    # ClamAV
    services.clamav = ClamAVClient(
        host=settings.clamav.host,
        port=settings.clamav.port,
        unix_socket=settings.clamav.unix_socket,
        timeout=settings.clamav.timeout,
        max_file_size=settings.clamav.max_file_size,
        enabled=settings.clamav.enabled,
    )
    if settings.clamav.enabled:
        if await services.clamav.health_check():
            logger.info("✓ ClamAV connecté")
        else:
            logger.warning("ClamAV configuré mais inaccessible — détection AV désactivée pour ce run")

    # MISP
    services.misp = MISPClient(
        misp_url=settings.misp_url,
        api_key=settings.misp_api_key,
        verify_ssl=settings.misp_verify_ssl,
    )
    logger.info("✓ MISP client → %s", settings.misp_url)

    # CAPE
    services.cape = CAPEClient(
        cape_url=settings.cape_api_url,
        api_token=settings.cape_api_token,
        timeout=settings.cape_timeout,
    )
    logger.info("✓ CAPE client → %s", settings.cape_api_url)

    # Orchestrateur
    services.orchestrator = OrchestratorService(
        cache=services.cache,
        heuristic=services.heuristic,
        misp=services.misp,
        cape=services.cape,
        yara=services.yara,
        clamav=services.clamav,
        score_threshold_allow=settings.score_threshold_allow,
        score_threshold_suspect=settings.score_threshold_suspect,
        score_threshold_block=settings.score_threshold_block,
    )
    services.stats = StatsService()
    services.api_keys = APIKeyService()
    logger.info("✓ Orchestrator + Stats + Auth prêts")

    # Scheduler Graph
    if settings.schedule.enabled and settings.azure.is_configured:
        graph = GraphClient(
            tenant_id=settings.azure.tenant_id,
            client_id=settings.azure.client_id,
            client_secret=settings.azure.client_secret,
        )
        services.scheduler = GraphScheduler(
            orchestrator=services.orchestrator,
            graph_client=graph,
            tenant_id=settings.azure.tenant_id,
            interval_minutes=settings.schedule.interval_minutes,
            emails_per_user=settings.schedule.emails_per_user,
            max_users=settings.schedule.max_users_per_scan,
            differential=settings.schedule.differential,
        )
        services.scheduler.start()
        logger.info("✓ Scheduler Graph démarré")
    else:
        logger.info("Scheduler Graph désactivé (SCHEDULE_ENABLED=false ou Azure non configuré)")

    yield  # ── runtime ──

    # Shutdown
    if services.scheduler:
        await services.scheduler.shutdown()
    await services.cache.disconnect()
    await dispose_engine()
    logger.info("Services arrêtés proprement")


# ─────────────────────────────────────────────────────────────
#  App
# ─────────────────────────────────────────────────────────────

settings = get_settings()
app = FastAPI(
    title="MailGuardianX Orchestrator",
    description=(
        "API d'orchestration pour la défense anti-ransomware dans les "
        "établissements de santé. Pipeline : Cache → Heuristique → YARA → "
        "ClamAV → MISP → CAPE Sandbox."
    ),
    version=settings.app_version,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-Agent-ID", "X-API-Key"],
)

# Métriques Prometheus
Instrumentator(
    should_group_status_codes=False,
    excluded_handlers=["/health", "/metrics"],
).instrument(app).expose(app, endpoint="/metrics")


# ─────────────────────────────────────────────────────────────
#  Dépendances FastAPI
# ─────────────────────────────────────────────────────────────

async def verify_api_key(
    db: AsyncSession = Depends(get_session),
    x_api_key: str = Header(..., alias="X-API-Key"),
) -> AuthenticatedKey:
    """Vérifie la clé API bcrypt contre la table api_keys."""
    if not x_api_key or len(x_api_key) < 16:
        raise HTTPException(status_code=401, detail="Invalid API key format")
    key = await services.api_keys.verify(db, x_api_key)
    if key is None:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key")
    return key


async def rate_limit_check(
    x_agent_id: str = Header(..., alias="X-Agent-ID"),
) -> str:
    allowed = await services.cache.check_rate_limit(x_agent_id)
    if not allowed:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    return x_agent_id


def require_scope(scope: str):
    """Dépendance : exige une clé API valide PORTANT le scope demandé (ou 'admin')."""
    async def _dep(key: AuthenticatedKey = Depends(verify_api_key)) -> AuthenticatedKey:
        if scope not in key.scopes and "admin" not in key.scopes:
            raise HTTPException(status_code=403, detail=f"Scope requis : {scope}")
        return key
    return _dep


async def authorize_key_creation(
    db: AsyncSession = Depends(get_session),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> None:
    """
    Création de clé API : libre UNIQUEMENT au bootstrap (aucune clé active en base).
    Dès qu'une clé existe, une clé valide avec scope 'admin' est exigée.
    """
    existing = await services.api_keys.count_active(db)
    if existing == 0:
        return  # bootstrap de la toute première clé
    if not x_api_key:
        raise HTTPException(status_code=401, detail="X-API-Key requis")
    key = await services.api_keys.verify(db, x_api_key)
    if key is None or "admin" not in key.scopes:
        raise HTTPException(status_code=403, detail="Scope admin requis")


# ─────────────────────────────────────────────────────────────
#  Endpoints publics
# ─────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    return {
        "service": services.settings.app_name if services.settings else "MailGuardianX",
        "version": settings.app_version,
        "status": "operational",
        "timestamp": datetime.utcnow().isoformat(),
        "pipeline": "Cache → Heuristic → YARA → ClamAV → MISP → CAPE",
    }


@app.get("/health")
async def health_check():
    """Health check réel : ping chaque service."""
    redis_ok = await services.cache.health_check() if hasattr(services, "cache") else False
    cape_ok = await services.cape.health_check() if hasattr(services, "cape") else False
    misp_ok = await services.misp.health_check() if hasattr(services, "misp") else False
    clamav_ok = await services.clamav.health_check() if hasattr(services, "clamav") else False
    yara_ok = services.yara.health_check() if hasattr(services, "yara") else False
    scheduler_ok = services.scheduler is not None and services.scheduler._running

    services_state = {
        "api": "up",
        "redis": "up" if redis_ok else "down",
        "cape": "up" if cape_ok else "down",
        "misp": "up" if misp_ok else "down",
        "clamav": "up" if clamav_ok else "disabled/down",
        "yara": "up" if yara_ok else "disabled",
        "scheduler": "up" if scheduler_ok else "disabled",
    }
    all_critical_up = redis_ok  # Redis seul est bloquant
    status_code = 200 if all_critical_up else 503

    return JSONResponse(
        status_code=status_code,
        content={
            "status": "healthy" if all_critical_up else "degraded",
            "timestamp": datetime.utcnow().isoformat(),
            "services": services_state,
        },
    )


# ─────────────────────────────────────────────────────────────
#  Endpoints d'analyse
# ─────────────────────────────────────────────────────────────

@app.post("/api/v1/analyze", response_model=AnalysisResponse)
async def analyze_email(
    request: AnalysisRequest,
    _: AuthenticatedKey = Depends(require_scope("analyze")),
    agent_id: str = Depends(rate_limit_check),
):
    """Analyse metadata-only — hash + métadonnées seuls, sans contenu de fichier.

    Source d'ingestion nominale = tenant M365 via Graph (scheduler). Ce endpoint
    sert les intégrations qui ne fournissent qu'un hash + métadonnées."""
    try:
        return await services.orchestrator.analyze(request)
    except Exception as exc:
        logger.exception("Analyze error : %s", exc)
        raise HTTPException(status_code=500, detail="Internal analysis error")


@app.post("/api/v1/upload")
async def upload_for_deep_analysis(
    task_id: str = Form(...),
    sha256: str = Form(...),
    agent_id: str = Form(...),
    file: UploadFile = File(...),
    _: AuthenticatedKey = Depends(require_scope("upload")),
):
    """Upload PJ — déclenche YARA + ClamAV + CAPE (chemin profond)."""
    contents = await file.read()
    max_size = services.settings.cape_max_file_size
    if len(contents) > max_size:
        raise HTTPException(
            status_code=413,
            detail=f"File too large ({len(contents)} > {max_size})",
        )

    try:
        verdict = await services.orchestrator.analyze_with_cape(
            task_id=task_id, sha256=sha256.lower(),
            file_data=contents, filename=file.filename or "sample.bin",
        )
        return {
            "task_id": task_id,
            "verdict": verdict.verdict.value,
            "confidence": verdict.confidence,
            "threat_name": verdict.threat_name,
            "signatures": verdict.signatures_matched,
            "analysis_source": verdict.analysis_source,
            "cape_task_id": verdict.cape_task_id,
        }
    except Exception as exc:
        logger.exception("Deep analysis error : %s", exc)
        raise HTTPException(status_code=500, detail="Deep analysis failed")


@app.post("/api/v1/upload/async")
async def upload_for_async_analysis(
    sha256: str = Form(...),
    file: UploadFile = File(...),
    _: AuthenticatedKey = Depends(require_scope("upload")),
):
    """Upload PJ en mode async (Celery) — retourne immédiatement un celery_task_id."""
    contents = await file.read()
    max_size = services.settings.cape_max_file_size
    if len(contents) > max_size:
        raise HTTPException(status_code=413, detail="File too large")

    from orchestrator.tasks.cape_tasks import analyze_attachment_task
    payload = base64.b64encode(contents).decode("ascii")
    job = analyze_attachment_task.delay(
        sha256.lower(), file.filename or "sample.bin", payload,
    )
    return {"celery_task_id": job.id, "status": "queued"}


@app.get("/api/v1/verdict/{task_id}")
async def get_verdict(
    task_id: str,
    _: AuthenticatedKey = Depends(verify_api_key),
):
    """Récupère un verdict mis en cache par task_id."""
    cached = await services.cache.get_task_verdict(task_id)
    if cached:
        return cached
    raise HTTPException(status_code=404, detail=f"No verdict found for task {task_id}")


@app.get("/api/v1/celery/{job_id}")
async def get_celery_result(
    job_id: str,
    _: AuthenticatedKey = Depends(verify_api_key),
):
    """Récupère le résultat d'une tâche Celery (analyse asynchrone)."""
    from orchestrator.celery_app import celery_app
    result = celery_app.AsyncResult(job_id)
    if not result.ready():
        return {"job_id": job_id, "status": result.status}
    if result.failed():
        return {"job_id": job_id, "status": "FAILED", "error": str(result.info)}
    return {"job_id": job_id, "status": "SUCCESS", "result": result.result}


# ─────────────────────────────────────────────────────────────
#  Stats + admin
# ─────────────────────────────────────────────────────────────

@app.get("/api/v1/stats", response_model=DashboardStats)
async def get_statistics(
    window_hours: int = 24,
    db: AsyncSession = Depends(get_session),
    _: AuthenticatedKey = Depends(verify_api_key),
):
    return await services.stats.compute(db, window_hours=window_hours)


@app.get("/api/v1/sessions")
async def list_sessions(
    limit: int = 20,
    db: AsyncSession = Depends(get_session),
    _: AuthenticatedKey = Depends(verify_api_key),
):
    return await services.stats.recent_sessions(db, limit=limit)


@app.post("/api/v1/scan/trigger")
async def trigger_scan_now(
    _: AuthenticatedKey = Depends(require_scope("admin")),
):
    """Force un scan Graph maintenant (hors planning)."""
    if services.scheduler is None:
        raise HTTPException(
            status_code=503,
            detail="Scheduler désactivé — configurer Azure AD + SCHEDULE_ENABLED=true",
        )
    await services.scheduler.trigger_now()
    return {"status": "triggered"}


@app.post("/api/v1/whitelist/{sha256}")
async def whitelist_hash(
    sha256: str,
    _: AuthenticatedKey = Depends(require_scope("admin")),
):
    await services.cache.set_hash_verdict(
        sha256.lower(), Verdict.ALLOW,
        source="whitelist", confidence=1.0, ttl=86400 * 30,
    )
    return {"status": "whitelisted", "sha256": sha256.lower()}


@app.post("/api/v1/blacklist/{sha256}")
async def blacklist_hash(
    sha256: str,
    threat_name: str = "Manual/Blacklist",
    _: AuthenticatedKey = Depends(require_scope("admin")),
):
    await services.cache.set_hash_verdict(
        sha256.lower(), Verdict.BLOCK,
        threat_name=threat_name, confidence=1.0,
        source="blacklist", ttl=86400 * 365,
    )
    return {"status": "blacklisted", "sha256": sha256.lower()}


# ─────────────────────────────────────────────────────────────
#  Admin API keys (à protéger en prod : reverse-proxy + IP allowlist)
# ─────────────────────────────────────────────────────────────

@app.post("/api/v1/admin/keys")
async def create_api_key(
    name: str = Form(...),
    scopes: Optional[str] = Form(None),
    db: AsyncSession = Depends(get_session),
    _: None = Depends(authorize_key_creation),
):
    """Crée une nouvelle clé API.

    Bootstrap : non-authentifié UNIQUEMENT tant qu'aucune clé n'existe en base.
    Dès la première clé créée, ce endpoint exige une clé valide avec scope 'admin'."""
    scope_list = [s.strip() for s in (scopes or "").split(",") if s.strip()]
    issued = await services.api_keys.create(db, name=name, scopes=scope_list)
    return {
        "id": issued.id,
        "name": issued.name,
        "prefix": issued.prefix,
        "scopes": issued.scopes,
        "key": issued.plaintext,
        "warning": "Cette clé ne sera plus jamais affichée — stockez-la maintenant.",
    }


@app.get("/api/v1/admin/keys")
async def list_api_keys(
    db: AsyncSession = Depends(get_session),
    _: AuthenticatedKey = Depends(require_scope("admin")),
):
    return await services.api_keys.list_active(db)


@app.delete("/api/v1/admin/keys/{key_id}")
async def revoke_api_key(
    key_id: int,
    db: AsyncSession = Depends(get_session),
    _: AuthenticatedKey = Depends(require_scope("admin")),
):
    ok = await services.api_keys.revoke(db, key_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Key not found or already revoked")
    return {"status": "revoked", "id": key_id}


# ─────────────────────────────────────────────────────────────
#  Entrypoint dev
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.api_host, port=settings.api_port)
