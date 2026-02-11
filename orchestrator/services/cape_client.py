"""
Client CAPE Sandbox.
Gère la soumission de fichiers, le polling de résultats,
et l'interprétation des rapports CAPE en verdicts.
"""
import asyncio
import logging
from typing import Optional
import httpx

from orchestrator.models.schemas import Verdict

logger = logging.getLogger(__name__)

# Signatures CAPE qui indiquent du ransomware
RANSOMWARE_SIGNATURES = {
    "ransomware_fileextensions",
    "ransomware_recyclebin",
    "ransomware_shadowcopy",
    "ransomware_bcdedit",
    "ransomware_message",
    "ransomware_dmalocker",
    "ransomware_extensions",
    "modifies_wallpaper",
    "deletes_shadow_copies",
    "encrypts_files",
    "stops_service",
    "creates_exe",
    "persistence_autorun",
    "injection_createremotethread",
    "injection_rwx",
    "antiav_detectreg",
    "antidebug_windows",
}

# Poids des signatures pour scoring
SIGNATURE_WEIGHTS = {
    "ransomware_": 0.40,     # Toute signature commençant par ransomware_
    "encrypts_": 0.35,
    "deletes_shadow": 0.35,
    "injection_": 0.25,
    "persistence_": 0.20,
    "creates_exe": 0.15,
    "antiav_": 0.15,
    "antidebug_": 0.10,
}


class CAPEClient:
    """Client async pour l'API CAPE Sandbox v2."""

    def __init__(
        self,
        cape_url: str = "http://cape:8000",
        api_token: Optional[str] = None,
        timeout: int = 30,
    ):
        self.cape_url = cape_url.rstrip("/")
        self.api_token = api_token
        self.timeout = timeout
        self._headers = {}
        if api_token:
            self._headers["Authorization"] = f"Token {api_token}"

    # ──────────────────── Soumission ────────────────────

    async def submit_file(
        self,
        file_data: bytes,
        filename: str = "sample.bin",
        timeout: int = 120,
        priority: int = 3,
        tags: str = "ransomware,auto",
    ) -> dict:
        """
        Soumet un fichier à CAPE pour analyse dynamique.
        Returns: {"task_id": int, "status": "submitted"} ou erreur.
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.cape_url}/apiv2/tasks/create/file/",
                    files={"file": (filename, file_data)},
                    data={
                        "timeout": timeout,
                        "priority": priority,
                        "tags": tags,
                        "options": "unpacker=2,procmemdump=yes",
                    },
                    headers=self._headers,
                )

            if response.status_code == 200:
                result = response.json()
                task_id = result.get("data", {}).get("task_ids", [None])[0]
                if task_id is None:
                    task_id = result.get("task_id")

                if task_id:
                    logger.info(f"CAPE submit OK → task_id={task_id}")
                    return {"task_id": task_id, "status": "submitted"}
                else:
                    logger.error(f"CAPE submit: no task_id in response: {result}")
                    return {"task_id": None, "status": "error", "message": "No task_id returned"}
            else:
                logger.error(f"CAPE submit failed: {response.status_code} {response.text[:200]}")
                return {
                    "task_id": None,
                    "status": "error",
                    "message": f"HTTP {response.status_code}",
                }

        except httpx.TimeoutException:
            logger.error("CAPE submit timeout")
            return {"task_id": None, "status": "error", "message": "Connection timeout"}
        except Exception as e:
            logger.error(f"CAPE submit exception: {e}")
            return {"task_id": None, "status": "error", "message": str(e)}

    # ──────────────────── Récupération rapport ────────────────────

    async def get_task_status(self, task_id: int) -> Optional[str]:
        """Vérifie le statut d'une tâche CAPE."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.cape_url}/apiv2/tasks/status/{task_id}/",
                    headers=self._headers,
                )
            if response.status_code == 200:
                data = response.json()
                return data.get("data", data.get("status", "unknown"))
            return None
        except Exception as e:
            logger.error(f"CAPE status check error: {e}")
            return None

    async def get_report(self, task_id: int) -> Optional[dict]:
        """Récupère le rapport JSON complet d'une analyse."""
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                response = await client.get(
                    f"{self.cape_url}/apiv2/tasks/get/report/{task_id}/",
                    headers=self._headers,
                )
            if response.status_code == 200:
                return response.json()
            logger.warning(f"CAPE report {task_id}: HTTP {response.status_code}")
            return None
        except Exception as e:
            logger.error(f"CAPE report error: {e}")
            return None

    # ──────────────────── Polling (attente résultat) ────────────────────

    async def wait_for_completion(
        self, task_id: int, max_wait: int = 600, poll_interval: int = 10
    ) -> bool:
        """Attend qu'une analyse CAPE soit terminée."""
        elapsed = 0
        while elapsed < max_wait:
            status = await self.get_task_status(task_id)
            if status in ("reported", "completed", "finished"):
                logger.info(f"CAPE task {task_id} completed after {elapsed}s")
                return True
            if status in ("failed_analysis", "failed_processing"):
                logger.error(f"CAPE task {task_id} failed: {status}")
                return False
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval
        logger.warning(f"CAPE task {task_id} timed out after {max_wait}s")
        return False

    # ──────────────────── Interprétation rapport → verdict ────────────────────

    def interpret_report(self, report: dict) -> dict:
        """
        Transforme un rapport CAPE en verdict + score.
        C'est ICI que la vraie valeur de l'analyse dynamique se traduit.
        """
        report_data = report.get("data", report.get("report", report))

        # Extraire les signatures
        signatures = report_data.get("signatures", [])
        sig_names = {s.get("name", "").lower() for s in signatures}

        # Calculer le score basé sur les signatures
        cape_score = 0.0
        matched = []
        for sig_name in sig_names:
            for pattern, weight in SIGNATURE_WEIGHTS.items():
                if sig_name.startswith(pattern) or pattern in sig_name:
                    cape_score += weight
                    matched.append(sig_name)
                    break

        # Bonus si signature ransomware directe
        ransomware_hits = sig_names & RANSOMWARE_SIGNATURES
        if ransomware_hits:
            cape_score += 0.30
            matched.extend(ransomware_hits)

        # Analyser le comportement réseau (C2, DNS suspect)
        network = report_data.get("network", {})
        dns_queries = network.get("dns", [])
        http_requests = network.get("http", [])
        if len(dns_queries) > 20 or len(http_requests) > 30:
            cape_score += 0.10
            matched.append("excessive_network_activity")

        # Vérifier les dropped files
        dropped = report_data.get("dropped", [])
        if any(d.get("name", "").endswith(".exe") for d in dropped):
            cape_score += 0.15
            matched.append("drops_executable")

        # Score CAPE du rapport (malscore)
        malscore = report_data.get("malscore", report_data.get("info", {}).get("score", 0))
        if isinstance(malscore, (int, float)):
            # CAPE score est sur 10, normaliser
            normalized_malscore = min(malscore / 10.0, 1.0)
            cape_score = max(cape_score, normalized_malscore)

        cape_score = min(cape_score, 1.0)

        # Déterminer le verdict
        if cape_score >= 0.7:
            verdict = Verdict.BLOCK
        elif cape_score >= 0.4:
            verdict = Verdict.QUARANTINE
        elif cape_score >= 0.2:
            verdict = Verdict.SUSPECT
        else:
            verdict = Verdict.ALLOW

        # Nommer la menace
        threat_name = None
        if ransomware_hits:
            threat_name = f"Ransomware/{list(ransomware_hits)[0]}"
        elif matched:
            threat_name = f"Suspicious/{matched[0]}"

        return {
            "verdict": verdict,
            "cape_score": round(cape_score, 3),
            "confidence": round(min(cape_score + 0.1, 1.0), 3),
            "signatures_matched": list(set(matched)),
            "threat_name": threat_name,
            "malscore": malscore,
        }

    # ──────────────────── Pipeline complet ────────────────────

    async def analyze_and_verdict(
        self,
        file_data: bytes,
        filename: str = "sample.bin",
        max_wait: int = 600,
    ) -> dict:
        """Pipeline complet : submit → wait → report → verdict."""
        # Submit
        submit_result = await self.submit_file(file_data, filename)
        if submit_result["status"] != "submitted":
            return {
                "verdict": Verdict.ERROR,
                "cape_score": 0.0,
                "confidence": 0.0,
                "message": submit_result.get("message", "Submit failed"),
            }

        task_id = submit_result["task_id"]

        # Wait
        completed = await self.wait_for_completion(task_id, max_wait=max_wait)
        if not completed:
            return {
                "verdict": Verdict.TIMEOUT,
                "cape_score": 0.0,
                "confidence": 0.0,
                "cape_task_id": task_id,
                "message": "Analysis timed out",
            }

        # Report + interpret
        report = await self.get_report(task_id)
        if not report:
            return {
                "verdict": Verdict.ERROR,
                "cape_score": 0.0,
                "confidence": 0.0,
                "cape_task_id": task_id,
                "message": "Failed to retrieve report",
            }

        result = self.interpret_report(report)
        result["cape_task_id"] = task_id
        return result

    # ──────────────────── Health ────────────────────

    async def health_check(self) -> bool:
        """Vérifie que CAPE est accessible."""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(f"{self.cape_url}/apiv2/cuckoo/status/")
            return response.status_code == 200
        except Exception:
            return False
