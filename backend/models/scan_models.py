"""
WebGuard AI — Pydantic Models
"""
from pydantic import BaseModel, HttpUrl, Field, validator
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class ScanType(str, Enum):
    QUICK = "quick"
    FULL = "full"
    SECURITY_ONLY = "security_only"
    PERFORMANCE_ONLY = "performance_only"


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# ─── Request Models ───────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    url: str
    scan_type: ScanType = ScanType.FULL
    modules: Optional[List[str]] = None  # None = all modules
    notify_email: Optional[str] = None

    @validator("url")
    def validate_url(cls, v):
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v.rstrip("/")


# ─── Finding Model ────────────────────────────────────────────────────────────

class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    category: str
    description: str
    evidence: Optional[str] = None
    fix: str
    references: Optional[List[str]] = []
    cve_ids: Optional[List[str]] = []
    cvss_score: Optional[float] = None


# ─── Sub-report Models ────────────────────────────────────────────────────────

class PerformanceReport(BaseModel):
    load_time_ms: int
    ttfb_ms: int
    page_size_kb: int
    requests: int
    compression: str
    caching: str
    cdn: str
    score: int


class SEOReport(BaseModel):
    title_tag: str
    meta_description: str
    h1_tags: int
    canonical: str
    sitemap: str
    robots_txt: str
    broken_links: int
    structured_data: str
    score: int


class SSLReport(BaseModel):
    valid: bool
    grade: str
    expires_days: int
    protocol: str
    hsts: str


class HeadersReport(BaseModel):
    x_frame_options: str
    csp: str
    x_content_type: str
    referrer_policy: str
    permissions_policy: str


class Technology(BaseModel):
    name: str
    version: str = "unknown"
    vulnerable: bool = False
    cve: Optional[str] = None


class ScanStats(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total_checks: int = 0
    passed: int = 0


# ─── Full Scan Result ─────────────────────────────────────────────────────────

class ScanResult(BaseModel):
    scan_id: str
    url: str
    hostname: str
    status: ScanStatus
    scan_type: ScanType
    created_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None

    overall_score: Optional[int] = None
    risk_level: Optional[RiskLevel] = None
    summary: Optional[str] = None

    stats: Optional[ScanStats] = None
    findings: Optional[List[Finding]] = []
    performance: Optional[PerformanceReport] = None
    seo: Optional[SEOReport] = None
    ssl: Optional[SSLReport] = None
    headers: Optional[HeadersReport] = None
    technologies: Optional[List[Technology]] = []

    error: Optional[str] = None


# ─── API Responses ────────────────────────────────────────────────────────────

class ScanInitResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    message: str
    poll_url: str
