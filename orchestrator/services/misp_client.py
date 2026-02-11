"""
Client MISP pour enrichissement threat intelligence.
Lookup de hash, domaines, IPs contre les IOCs connus.
"""
import logging
from typing import Optional
import httpx

from orchestrator.models.schemas import Verdict

logger = logging.getLogger(__name__)


class MISPClient:
    """Client async pour l'API MISP."""

    def __init__(
        self,
        misp_url: str = "http://misp:80",
        api_key: Optional[str] = None,
        verify_ssl: bool = False,
    ):
        self.misp_url = misp_url.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self._headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if api_key:
            self._headers["Authorization"] = api_key

    async def search_hash(self, sha256: str) -> dict:
        """
        Cherche un hash dans MISP.
        Returns: {"found": bool, "verdict": Verdict, "threat_name": str, "events": [...]}
        """
        try:
            async with httpx.AsyncClient(
                timeout=15, verify=self.verify_ssl
            ) as client:
                response = await client.post(
                    f"{self.misp_url}/attributes/restSearch",
                    json={
                        "value": sha256,
                        "type": ["sha256", "filename|sha256"],
                        "limit": 5,
                        "includeEventTags": True,
                    },
                    headers=self._headers,
                )

            if response.status_code != 200:
                logger.warning(f"MISP search failed: HTTP {response.status_code}")
                return {"found": False, "misp_score": 0.0}

            data = response.json()
            attributes = data.get("response", {}).get("Attribute", [])

            if not attributes:
                return {"found": False, "misp_score": 0.0}

            # Analyser les résultats
            events = []
            threat_level_sum = 0
            for attr in attributes:
                event = attr.get("Event", {})
                events.append({
                    "event_id": event.get("id"),
                    "info": event.get("info", ""),
                    "threat_level_id": event.get("threat_level_id"),
                })
                # MISP threat levels: 1=High, 2=Medium, 3=Low, 4=Undefined
                tl = int(event.get("threat_level_id", 4))
                threat_level_sum += (5 - tl) / 4  # Normaliser: 1→1.0, 2→0.75, 3→0.5, 4→0.25

            avg_threat = threat_level_sum / len(attributes) if attributes else 0
            misp_score = min(avg_threat, 1.0)

            # Tags ransomware ?
            tags = []
            for attr in attributes:
                for tag in attr.get("Tag", []):
                    tags.append(tag.get("name", ""))

            is_ransomware = any("ransomware" in t.lower() for t in tags)
            threat_name = None
            if is_ransomware:
                misp_score = max(misp_score, 0.90)
                threat_name = f"MISP/Ransomware ({events[0]['info'][:50]})" if events else "MISP/Ransomware"
            elif misp_score > 0.5:
                threat_name = f"MISP/{events[0]['info'][:50]}" if events else "MISP/Unknown"

            if misp_score >= 0.7:
                verdict = Verdict.BLOCK
            elif misp_score >= 0.4:
                verdict = Verdict.SUSPECT
            else:
                verdict = Verdict.ALLOW

            logger.info(f"MISP hit for {sha256[:16]}...: score={misp_score:.2f}, events={len(events)}")

            return {
                "found": True,
                "verdict": verdict,
                "misp_score": round(misp_score, 3),
                "threat_name": threat_name,
                "events": events[:5],
                "tags": tags[:20],
            }

        except httpx.TimeoutException:
            logger.warning("MISP search timeout")
            return {"found": False, "misp_score": 0.0, "error": "timeout"}
        except Exception as e:
            logger.error(f"MISP search error: {e}")
            return {"found": False, "misp_score": 0.0, "error": str(e)}

    async def search_domain(self, domain: str) -> dict:
        """Cherche un domaine expéditeur dans MISP."""
        try:
            async with httpx.AsyncClient(
                timeout=10, verify=self.verify_ssl
            ) as client:
                response = await client.post(
                    f"{self.misp_url}/attributes/restSearch",
                    json={
                        "value": domain,
                        "type": ["domain", "hostname"],
                        "limit": 3,
                    },
                    headers=self._headers,
                )

            if response.status_code == 200:
                data = response.json()
                attributes = data.get("response", {}).get("Attribute", [])
                if attributes:
                    return {"found": True, "malicious_domain": True, "hit_count": len(attributes)}

            return {"found": False, "malicious_domain": False}

        except Exception as e:
            logger.error(f"MISP domain search error: {e}")
            return {"found": False, "malicious_domain": False}

    async def health_check(self) -> bool:
        """Vérifie que MISP est accessible."""
        try:
            async with httpx.AsyncClient(
                timeout=5, verify=self.verify_ssl
            ) as client:
                response = await client.get(
                    f"{self.misp_url}/servers/getVersion",
                    headers=self._headers,
                )
            return response.status_code == 200
        except Exception:
            return False
