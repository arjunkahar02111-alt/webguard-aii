"""
WebGuard AI — Scanner module re-export shims.
scan_tasks.py imports these as separate modules;
they proxy to the consolidated implementations.
"""

# ── security/headers.py ──────────────────────────────────────────────────────
from scanners.security.xss import HeadersScanner

# ── security/ssl_tls.py ──────────────────────────────────────────────────────
from scanners.security.xss import SSLScanner

# ── security/cors.py ─────────────────────────────────────────────────────────
from scanners.security.xss import CORSScanner

# ── security/cookies.py ──────────────────────────────────────────────────────
from scanners.security.xss import CookieScanner

# ── security/auth.py ─────────────────────────────────────────────────────────
from scanners.security.xss import AuthScanner

# ── security/idor.py ─────────────────────────────────────────────────────────
from scanners.security.xss import IDORScanner

# ── security/open_redirect.py ────────────────────────────────────────────────
from scanners.security.xss import OpenRedirectScanner

# ── security/ssrf.py ─────────────────────────────────────────────────────────
from scanners.security.xss import SSRFScanner

# ── security/traversal.py ────────────────────────────────────────────────────
from scanners.security.xss import TraversalScanner

# ── security/clickjacking.py ─────────────────────────────────────────────────
from scanners.security.xss import ClickjackingScanner

# ── security/file_upload.py ──────────────────────────────────────────────────
from scanners.security.xss import FileUploadScanner

# ── security/api_security.py ─────────────────────────────────────────────────
from scanners.security.xss import APISecurityScanner

# ── security/dependencies.py ─────────────────────────────────────────────────
from scanners.security.xss import DependencyScanner

# ── security/subdomain.py ────────────────────────────────────────────────────
from scanners.security.xss import SubdomainScanner

# ── security/dns_check.py ────────────────────────────────────────────────────
from scanners.security.xss import DNSScanner

__all__ = [
    "HeadersScanner", "SSLScanner", "CORSScanner", "CookieScanner",
    "AuthScanner", "IDORScanner", "OpenRedirectScanner", "SSRFScanner",
    "TraversalScanner", "ClickjackingScanner", "FileUploadScanner",
    "APISecurityScanner", "DependencyScanner", "SubdomainScanner", "DNSScanner",
]
