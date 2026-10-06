"""Threat-intelligence lookups.

Live mode talks to the configured providers only. When a provider is not
configured the result says so (``status: NOT_CONFIGURED``) and when a provider
fails it says that (``status: ERROR``) - no catalog of made-up verdicts is ever
consulted outside DEMO_MODE. The MCP client (or the analyst) decides what to do
with an unknown indicator; usually another intel tool is available to it.
"""
import logging
from typing import Any, Dict

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

PRIVATE_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.3", "127.", "169.254.", "fc", "fd", "fe80", "::1")


def _not_configured(provider: str, setting: str, **ctx: Any) -> Dict[str, Any]:
    return {
        **ctx,
        "status": "NOT_CONFIGURED",
        "provider": provider,
        "verdict": "UNKNOWN",
        "message": f"{provider} is not configured on this server, so no reputation was looked up.",
        "what_to_check": [
            f"Optional: set {setting} in backend/.env to enable {provider} lookups.",
            "If your MCP client has another threat-intelligence tool, use that for this indicator.",
        ],
    }


def _error(provider: str, detail: str, **ctx: Any) -> Dict[str, Any]:
    return {
        **ctx,
        "status": "ERROR",
        "provider": provider,
        "verdict": "UNKNOWN",
        "message": f"{provider} lookup failed; no verdict.",
        "what_to_check": ["Retry once; if it keeps failing the API key may be invalid or the provider is down."],
        "detail": detail[:500],
    }


class ThreatIntelService:
    def __init__(self):
        self.abuseipdb_key = settings.ABUSEIPDB_API_KEY
        self.virustotal_key = settings.VIRUSTOTAL_API_KEY
        self.microsoft_ti_enabled = settings.ENABLE_MICROSOFT_THREAT_INTEL

    # ------------------------------------------------------------------ IPs
    async def lookup_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        ip = (ip_address or "").strip()
        if ip.lower().startswith(PRIVATE_PREFIXES):
            return {
                "ip": ip, "status": "SUCCESS", "is_private": True, "abuse_confidence_score": 0, "total_reports": 0,
                "country": "Internal Network (RFC 1918 / link-local)", "isp": "Private address space",
                "usage_type": "Private IP", "verdict": "BENIGN_INTERNAL",
            }

        if settings.DEMO_MODE:
            return self._demo_ip(ip)

        if not self.abuseipdb_key:
            return _not_configured("AbuseIPDB", "ABUSEIPDB_API_KEY", ip=ip, is_private=False)
        try:
            headers = {"Key": self.abuseipdb_key, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": True}
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
            if resp.status_code != 200:
                return _error("AbuseIPDB", f"HTTP {resp.status_code}: {resp.text}", ip=ip, is_private=False)
            data = resp.json().get("data", {})
            score = int(data.get("abuseConfidenceScore", 0) or 0)
            return {
                "ip": ip, "status": "SUCCESS", "provider": "AbuseIPDB", "is_private": False,
                "abuse_confidence_score": score, "total_reports": data.get("totalReports", 0),
                "country": data.get("countryCode", "Unknown"), "isp": data.get("isp", "Unknown"),
                "usage_type": data.get("usageType", "Unknown"), "is_whitelisted": data.get("isWhitelisted", False),
                "last_reported": data.get("lastReportedAt"),
                "verdict": "MALICIOUS" if score > 70 else "SUSPICIOUS" if score > 25 else "CLEAN",
            }
        except Exception as e:  # noqa: BLE001
            logger.warning("AbuseIPDB lookup failed for %s: %s", ip, e)
            return _error("AbuseIPDB", f"{type(e).__name__}: {e}", ip=ip, is_private=False)

    # --------------------------------------------------------------- hashes
    async def lookup_file_hash(self, sha256_or_md5: str) -> Dict[str, Any]:
        h = (sha256_or_md5 or "").strip().lower()
        if settings.DEMO_MODE:
            return self._demo_hash(h)
        if not self.virustotal_key:
            return _not_configured("VirusTotal", "VIRUSTOTAL_API_KEY", hash=h)
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(f"https://www.virustotal.com/api/v3/files/{h}", headers={"x-apikey": self.virustotal_key})
            if resp.status_code == 404:
                return {"hash": h, "status": "SUCCESS", "provider": "VirusTotal", "known": False, "malicious_engines": 0,
                        "total_engines": 0, "verdict": "UNKNOWN", "message": "VirusTotal has never seen this hash."}
            if resp.status_code != 200:
                return _error("VirusTotal", f"HTTP {resp.status_code}: {resp.text}", hash=h)
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0) or 0)
            return {
                "hash": h, "status": "SUCCESS", "provider": "VirusTotal", "known": True,
                "malicious_engines": malicious, "total_engines": sum(int(v or 0) for v in stats.values()),
                "popular_threat_name": attrs.get("popular_threat_classification", {}).get("suggested_threat_label"),
                "meaningful_name": attrs.get("meaningful_name"),
                "first_submission": attrs.get("first_submission_date"),
                "verdict": "MALICIOUS" if malicious >= 5 else "SUSPICIOUS" if malicious > 0 else "CLEAN",
            }
        except Exception as e:  # noqa: BLE001
            logger.warning("VirusTotal lookup failed for %s: %s", h, e)
            return _error("VirusTotal", f"{type(e).__name__}: {e}", hash=h)

    # ------------------------------------------------- Sentinel TI tables
    async def lookup_microsoft_threat_intel(self, indicator: str, indicator_type: str = "ip", workspace=None) -> Dict[str, Any]:
        """Match an indicator against the workspace's own threat-intelligence tables
        (ThreatIntelIndicators, then the legacy ThreatIntelligenceIndicator)."""
        if not self.microsoft_ti_enabled:
            return {"status": "DISABLED", "indicator": indicator, "message": "ENABLE_MICROSOFT_THREAT_INTEL is False."}
        from app.services.kql_runner import kql_runner
        from app.services.hunting_catalog import kql_string

        ind = kql_string(indicator)
        queries = [
            ("ThreatIntelIndicators", f"ThreatIntelIndicators | where IsActive == true and ValidUntil > now() | where ObservableValue =~ {ind} "
                                      "| summarize arg_max(TimeGenerated, ObservableKey, Confidence, SourceSystem, ValidUntil, Tags, Description=tostring(Data.description)) by Id | take 5"),
            ("ThreatIntelligenceIndicator", f"ThreatIntelligenceIndicator | where Active == true | where NetworkIP =~ {ind} or NetworkSourceIP =~ {ind} or NetworkDestinationIP =~ {ind} "
                                             f"or FileHashValue =~ {ind} or DomainName =~ {ind} or Url =~ {ind} "
                                             "| summarize arg_max(TimeGenerated, ThreatType, ConfidenceScore, Description, SourceSystem, ExpirationDateTime, Tags) by IndicatorId | take 5"),
        ]
        errors = []
        for table, q in queries:
            res = await kql_runner.execute_kql(q, timespan_hours=24 * 90, workspace=workspace)
            if res.get("status") == "SUCCESS":
                rows = (res.get("tables") or [{}])[0].get("rows") or []
                if rows:
                    return {"status": "SUCCESS", "source": table, "indicator": indicator, "type": indicator_type, "matches": rows, "verdict": "MATCHED"}
            else:
                errors.append({"table": table, "error_type": res.get("error_type"), "error": res.get("error")})
        if errors and len(errors) == len(queries):
            return {"status": "ERROR", "indicator": indicator, "type": indicator_type, "verdict": "UNKNOWN",
                    "message": "Neither TI table could be queried in this workspace.", "errors": errors}
        return {"status": "SUCCESS", "indicator": indicator, "type": indicator_type, "matches": [], "verdict": "NO_MATCH",
                "message": "No active indicator in the workspace's threat-intelligence tables.", "errors": errors}

    # ------------------------------------------------------------- demo data
    @staticmethod
    def _demo_ip(ip: str) -> Dict[str, Any]:
        known = {
            "185.220.101.5": {"score": 98, "country": "RU", "isp": "BadHost LLC", "reports": 342, "verdict": "MALICIOUS", "type": "Tor Exit Node / Brute Force"},
            "45.148.10.12": {"score": 88, "country": "NL", "isp": "Bulletproof Hosting Ltd", "reports": 115, "verdict": "MALICIOUS", "type": "Cobalt Strike C2 / Scanner"},
            "194.26.29.114": {"score": 92, "country": "UA", "isp": "HostService Group", "reports": 210, "verdict": "MALICIOUS", "type": "Password Spray / Botnet"},
            "8.8.8.8": {"score": 0, "country": "US", "isp": "Google LLC", "reports": 0, "verdict": "CLEAN", "type": "Public DNS"},
            "1.1.1.1": {"score": 0, "country": "US", "isp": "Cloudflare, Inc.", "reports": 0, "verdict": "CLEAN", "type": "Public DNS"},
        }
        info = known.get(ip, {"score": 15, "country": "US", "isp": "Commercial Hosting Provider", "reports": 2, "verdict": "LOW_RISK", "type": "Data Center"})
        return {"ip": ip, "status": "SUCCESS", "provider": "demo", "is_private": False, "abuse_confidence_score": info["score"],
                "total_reports": info["reports"], "country": info["country"], "isp": info["isp"], "usage_type": info["type"], "verdict": info["verdict"]}

    @staticmethod
    def _demo_hash(h: str) -> Dict[str, Any]:
        known = {
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {"malicious": 58, "total": 72, "label": "Trojan.Mimikatz.CredentialTheft", "verdict": "MALICIOUS"},
            "44d88612fea8a8f36de82e1278abb02f": {"malicious": 62, "total": 70, "label": "Ransomware.WannaCry", "verdict": "MALICIOUS"},
        }
        info = known.get(h, {"malicious": 0, "total": 70, "label": None, "verdict": "CLEAN_OR_UNKNOWN"})
        return {"hash": h, "status": "SUCCESS", "provider": "demo", "known": h in known, "malicious_engines": info["malicious"],
                "total_engines": info["total"], "popular_threat_name": info["label"], "verdict": info["verdict"]}


threat_intel_service = ThreatIntelService()
