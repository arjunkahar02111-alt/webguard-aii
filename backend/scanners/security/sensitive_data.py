"""
WebGuard AI — Session & Sensitive Data Exposure Scanner
Detects session fixation, expiry issues, and exposed sensitive endpoints/data.
"""
from scanners.base import BaseScanner
import re
import logging

logger = logging.getLogger(__name__)

SENSITIVE_PATTERNS = [
    (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', "Email Address", "MEDIUM"),
    (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b', "Credit Card Number", "CRITICAL"),
    (r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']?[^\s"\']+', "Password in Source", "CRITICAL"),
    (r'(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{16,}', "API Key/Secret", "CRITICAL"),
    (r'\b(?:\d{3}-\d{2}-\d{4}|\d{9})\b', "SSN Pattern", "HIGH"),
    (r'(?i)private[_-]?key|-----BEGIN (?:RSA |EC )?PRIVATE KEY', "Private Key Material", "CRITICAL"),
    (r'(?i)aws_access_key_id\s*=\s*[A-Z0-9]{20}', "AWS Access Key", "CRITICAL"),
    (r'(?i)mongodb(?:\+srv)?://[^"\s]+', "Database Connection String", "CRITICAL"),
    (r'(?i)(?:mysql|postgres|postgresql)://[^"\s]+', "Database Connection String", "CRITICAL"),
    (r'(?i)(?:debug|traceback|stack trace|exception in|internal server error)', "Debug Info Exposed", "HIGH"),
]

SENSITIVE_ENDPOINTS = [
    ("/config",          "Configuration File"),
    ("/.env",            "Environment File"),
    ("/config.php",      "PHP Config"),
    ("/wp-config.php",   "WordPress Config"),
    ("/config.yml",      "YAML Config"),
    ("/config.json",     "JSON Config"),
    ("/.git/config",     "Git Config"),
    ("/.git/HEAD",       "Git Repository"),
    ("/phpinfo.php",     "PHP Info Page"),
    ("/server-status",   "Apache Server Status"),
    ("/server-info",     "Apache Server Info"),
    ("/actuator",        "Spring Boot Actuator"),
    ("/actuator/env",    "Spring Actuator Env"),
    ("/actuator/health", "Spring Actuator Health"),
    ("/metrics",         "Metrics Endpoint"),
    ("/debug",           "Debug Endpoint"),
    ("/trace",           "Trace Endpoint"),
    ("/swagger-ui.html", "Swagger UI"),
    ("/backup",          "Backup Directory"),
    ("/dump.sql",        "Database Dump"),
    ("/backup.sql",      "Database Backup"),
    ("/backup.zip",      "Backup Archive"),
    ("/.DS_Store",       "macOS Metadata"),
    ("/Thumbs.db",       "Windows Thumbnail DB"),
]


class SensitiveDataScanner(BaseScanner):
    async def run(self):
        resp = await self.fetch(self.url)
        if resp:
            self._scan_body_for_sensitive(resp.text())

        await self._probe_sensitive_endpoints()
        await self._check_directory_listing()

        return self.result()

    def _scan_body_for_sensitive(self, body: str):
        found_types = set()
        for pattern, label, severity in SENSITIVE_PATTERNS:
            match = re.search(pattern, body)
            if match and label not in found_types:
                found_types.add(label)
                snippet = match.group(0)[:80]
                self.add_finding(
                    title=f"Sensitive Data Exposed in Page: {label}",
                    severity=severity,
                    category="Sensitive Data Exposure",
                    description=(
                        f"Pattern matching '{label}' was found in the page response. "
                        "Exposing sensitive data allows attackers to harvest credentials, "
                        "keys, or PII without requiring authentication."
                    ),
                    evidence=f"Found: {snippet}...",
                    fix=(
                        "Remove sensitive data from HTML/JS source immediately. "
                        "Use environment variables for secrets, never embed in code. "
                        "Audit all pages with automated scanning regularly."
                    ),
                    cvss_score={"CRITICAL": 9.8, "HIGH": 7.5, "MEDIUM": 5.3}.get(severity, 5.0),
                )

    async def _probe_sensitive_endpoints(self):
        for path, label in SENSITIVE_ENDPOINTS:
            resp = await self.fetch(self.url + path)
            if not resp:
                continue
            if resp.status == 200:
                body = resp.text().lower()
                # Avoid false positives from redirect pages
                if len(body) < 50 or "<html" in body[:100] and "404" in body[:500]:
                    continue
                self.add_finding(
                    title=f"Sensitive Endpoint Exposed: {path} ({label})",
                    severity="CRITICAL" if any(x in path for x in [".env", "wp-config", "dump.sql", "private"]) else "HIGH",
                    category="Sensitive Data Exposure",
                    description=(
                        f"The endpoint '{path}' ({label}) is publicly accessible. "
                        "This can expose credentials, configuration, source code, or database dumps "
                        "to unauthenticated attackers."
                    ),
                    evidence=f"GET {self.url + path} → HTTP 200 ({len(body)} bytes)",
                    fix=(
                        f"Immediately restrict access to '{path}'. "
                        "Move sensitive files outside the webroot. "
                        "Use .htaccess (Apache) or location blocks (Nginx) to deny access."
                    ),
                    cvss_score=9.8,
                )

    async def _check_directory_listing(self):
        resp = await self.fetch(self.url + "/images/")
        if not resp:
            resp = await self.fetch(self.url + "/static/")
        if not resp:
            return
        body = resp.text()
        if resp.status == 200 and (
            "Index of /" in body or
            "Directory listing for" in body or
            "Parent Directory" in body
        ):
            self.add_finding(
                title="Directory Listing Enabled",
                severity="MEDIUM",
                category="Security Misconfiguration",
                description=(
                    "Directory listing is enabled, allowing attackers to browse the server's "
                    "file system. This can reveal hidden files, backup archives, and sensitive content."
                ),
                evidence=f"Directory index page found at {self.url}/images/ or /static/",
                fix=(
                    "Disable directory listing: "
                    "Apache: Options -Indexes in .htaccess. "
                    "Nginx: remove 'autoindex on' directive. "
                    "Ensure all directories have an index file."
                ),
                cvss_score=5.3,
            )


class SessionScanner(BaseScanner):
    """Checks for session fixation and session expiry issues."""

    async def run(self):
        resp1 = await self.fetch(self.url)
        if not resp1:
            return self.result()

        cookie1 = resp1.headers.get("Set-Cookie", "")

        # Session fixation: check if session ID changes after a new visit
        resp2 = await self.fetch(self.url)
        if not resp2:
            return self.result()

        cookie2 = resp2.headers.get("Set-Cookie", "")

        # Extract session IDs
        sess_pat = re.compile(r'(?:session(?:id)?|sess|PHPSESSID|JSESSIONID)=([^;,\s]+)', re.IGNORECASE)
        match1 = sess_pat.search(cookie1)
        match2 = sess_pat.search(cookie2)

        if match1 and match2:
            if match1.group(1) == match2.group(1):
                self.add_finding(
                    title="Session ID Does Not Regenerate Between Requests",
                    severity="MEDIUM",
                    category="Session Management",
                    description=(
                        "The session ID is identical across two separate unauthenticated requests. "
                        "If the same token is assigned pre- and post-authentication, "
                        "session fixation attacks become possible."
                    ),
                    evidence=f"Session ID unchanged: {match1.group(1)[:20]}...",
                    fix=(
                        "Regenerate the session ID upon authentication. "
                        "In PHP: session_regenerate_id(true) after login. "
                        "In Express: req.session.regenerate() after login."
                    ),
                    cvss_score=6.8,
                )

        # Check for session expiry
        if cookie1:
            has_max_age = re.search(r'max-age\s*=\s*(\d+)', cookie1, re.IGNORECASE)
            has_expires = "expires" in cookie1.lower()
            if not has_max_age and not has_expires:
                self.add_finding(
                    title="Session Cookie Has No Expiry",
                    severity="LOW",
                    category="Session Management",
                    description=(
                        "Session cookie has no Max-Age or Expires attribute. "
                        "Without expiry, the session persists until the browser is closed. "
                        "On shared computers, this risks session hijacking."
                    ),
                    evidence=f"Set-Cookie: {cookie1[:150]}",
                    fix=(
                        "Set an appropriate expiry on session cookies: "
                        "Set-Cookie: session=...; Max-Age=3600; HttpOnly; Secure. "
                        "Also implement server-side session timeout."
                    ),
                )
            elif has_max_age:
                age = int(has_max_age.group(1))
                if age > 86400 * 30:  # More than 30 days
                    self.add_finding(
                        title=f"Session Cookie Expiry Too Long ({age // 86400} days)",
                        severity="LOW",
                        category="Session Management",
                        description=(
                            f"Session cookie expires in {age // 86400} days. "
                            "Long-lived sessions increase the window for session theft."
                        ),
                        evidence=f"Max-Age={age}",
                        fix="Reduce session lifetime. Use sliding expiry with server-side validation.",
                    )

        return self.result()
