"""
WebGuard AI — Base Scanner
All scanner modules inherit from this class.
"""
import aiohttp
import asyncio
from typing import Optional, Dict, Any
from core.config import settings
import logging

logger = logging.getLogger(__name__)


class BaseScanner:
    """
    Base class for all WebGuard AI scanner modules.
    
    Provides shared HTTP session, safe payload delivery,
    and standardised finding creation.
    """

    SAFE_PAYLOADS = True   # Never use destructive payloads

    def __init__(self, url: str):
        self.url = url.rstrip("/")
        self.findings = []
        self.session: Optional[aiohttp.ClientSession] = None
        self.timeout = aiohttp.ClientTimeout(total=settings.REQUEST_TIMEOUT_SECONDS)
        self.headers = {"User-Agent": settings.USER_AGENT}

    async def _get_session(self) -> aiohttp.ClientSession:
        if not self.session or self.session.closed:
            connector = aiohttp.TCPConnector(ssl=False, limit=10)
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=self.timeout,
                headers=self.headers,
            )
        return self.session

    async def fetch(self, url: str, method: str = "GET", **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Safe HTTP request with error handling."""
        session = await self._get_session()
        try:
            async with session.request(method, url, **kwargs) as response:
                # Read body while session is open
                body = await response.read()
                return _FakeResponse(response.status, dict(response.headers), body)
        except asyncio.TimeoutError:
            logger.debug(f"Timeout fetching {url}")
        except Exception as e:
            logger.debug(f"Error fetching {url}: {e}")
        return None

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()

    def add_finding(
        self,
        title: str,
        severity: str,
        category: str,
        description: str,
        fix: str,
        evidence: str = "",
        references: list = None,
        cve_ids: list = None,
        cvss_score: float = None,
    ):
        import uuid
        self.findings.append({
            "id": f"VULN-{uuid.uuid4().hex[:6].upper()}",
            "title": title,
            "severity": severity,
            "category": category,
            "description": description,
            "evidence": evidence,
            "fix": fix,
            "references": references or [],
            "cve_ids": cve_ids or [],
            "cvss_score": cvss_score,
        })

    async def run(self) -> Dict[str, Any]:
        """Override in subclasses. Return {"findings": [...], ...}"""
        raise NotImplementedError

    def result(self) -> Dict[str, Any]:
        return {"findings": self.findings}


class _FakeResponse:
    """Thin wrapper to hold response data after session close."""
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self._body = body

    def text(self, encoding="utf-8"):
        try:
            return self._body.decode(encoding, errors="replace")
        except Exception:
            return ""

    def __repr__(self):
        return f"<Response [{self.status}]>"
