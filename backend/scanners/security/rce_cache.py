"""
WebGuard AI — Cache Poisoning & RCE Detection Scanner
Probes for web cache poisoning indicators and remote code execution patterns.
"""
from scanners.base import BaseScanner
import re
import logging

logger = logging.getLogger(__name__)


class CachePoisoningScanner(BaseScanner):
    """
    Detects web cache poisoning indicators:
    - Unkeyed header reflection (X-Forwarded-Host, X-Original-URL)
    - Fat GET request handling
    - Vary header misconfigurations
    """

    UNKEYED_HEADERS = [
        ("X-Forwarded-Host",   "webguard-poison-probe.example"),
        ("X-Original-URL",     "/webguard-probe"),
        ("X-Rewrite-URL",      "/webguard-probe"),
        ("X-Forwarded-Scheme", "nothttps"),
        ("X-Host",             "webguard-poison-probe.example"),
    ]

    async def run(self):
        # Baseline
        baseline = await self.fetch(self.url)
        if not baseline:
            return self.result()

        baseline_body = baseline.text()

        for header_name, probe_val in self.UNKEYED_HEADERS:
            resp = await self.fetch(self.url, headers={header_name: probe_val})
            if not resp:
                continue
            body = resp.text()

            # If the probe value appears in the response body, the header is reflected
            if probe_val in body and probe_val not in baseline_body:
                self.add_finding(
                    title=f"Cache Poisoning Risk — Unkeyed Header Reflected: {header_name}",
                    severity="HIGH",
                    category="Cache Poisoning",
                    description=(
                        f"The header '{header_name}: {probe_val}' was reflected in the response body. "
                        "If this response is cached, an attacker can poison the cache with a "
                        "malicious host value, redirecting all users to a phishing/malware site."
                    ),
                    evidence=f"{header_name}: {probe_val} → probe value found in response",
                    fix=(
                        "Add the header to the cache key, or strip it at the edge/CDN. "
                        "In Varnish: set req.http.X-Forwarded-Host = req.http.Host; "
                        "Review all headers used in URL construction and ensure they are cache-keyed."
                    ),
                    cvss_score=8.1,
                )

        # Check Vary header for security-relevant omissions
        vary = baseline.headers.get("Vary", "")
        cache_ctrl = baseline.headers.get("Cache-Control", "")
        if cache_ctrl and "public" in cache_ctrl and "authorization" not in vary.lower():
            self.add_finding(
                title="Publicly Cacheable Response Without Vary: Authorization",
                severity="MEDIUM",
                category="Cache Poisoning",
                description=(
                    "Response is publicly cacheable (Cache-Control: public) but doesn't include "
                    "'Authorization' in the Vary header. Authenticated content may be served to "
                    "unauthenticated users from cache."
                ),
                evidence=f"Cache-Control: {cache_ctrl} | Vary: {vary or 'absent'}",
                fix=(
                    "Add 'Vary: Authorization' for authenticated responses, or use "
                    "'Cache-Control: private' for user-specific content."
                ),
                cvss_score=6.5,
            )

        return self.result()


class RCEScanner(BaseScanner):
    """
    Detects Remote Code Execution risk patterns:
    - Eval/exec patterns in JavaScript source
    - Template injection indicators
    - Dangerous deserialization hints
    - Debug/eval endpoints
    """

    RCE_ENDPOINTS = [
        "/eval", "/exec", "/run", "/execute", "/shell",
        "/api/exec", "/api/run", "/debug/eval",
    ]

    TEMPLATE_PAYLOADS = [
        ("{{7*7}}", "49", "Jinja2/Twig SSTI"),
        ("${7*7}", "49", "FreeMarker/EL SSTI"),
        ("<%=7*7%>", "49", "ERB SSTI"),
    ]

    DANGEROUS_JS_PATTERNS = [
        r"eval\s*\(\s*(?:location|document\.URL|window\.name)",
        r"Function\s*\(\s*['\"]return",
        r"setTimeout\s*\(\s*['\"]",
        r"setInterval\s*\(\s*['\"]",
        r"document\.write\s*\(\s*(?:location|document\.URL)",
    ]

    async def run(self):
        resp = await self.fetch(self.url)
        if resp:
            self._check_js_patterns(resp.text())
            await self._check_template_injection()

        await self._check_rce_endpoints()

        return self.result()

    def _check_js_patterns(self, body: str):
        for pattern in self.DANGEROUS_JS_PATTERNS:
            match = re.search(pattern, body)
            if match:
                self.add_finding(
                    title="Dangerous JavaScript Pattern — Potential DOM-Based RCE",
                    severity="HIGH",
                    category="RCE",
                    description=(
                        f"Potentially dangerous JavaScript pattern detected: '{match.group(0)[:80]}'. "
                        "Passing user-controlled data to eval(), Function(), setTimeout(string), "
                        "or setInterval(string) can lead to JavaScript injection / RCE in browser."
                    ),
                    evidence=f"Pattern: {match.group(0)[:120]}",
                    fix=(
                        "Never pass string arguments to eval(), Function(), setTimeout(), or setInterval(). "
                        "Use function references instead: setTimeout(myFunc, 1000) not setTimeout('myFunc()', 1000)."
                    ),
                    cvss_score=8.8,
                )
                break

    async def _check_template_injection(self):
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(self.url)
        qs = parse_qs(parsed.query)
        if not qs:
            return

        param = list(qs.keys())[0]
        for payload, expected, label in self.TEMPLATE_PAYLOADS:
            test_qs = dict(qs)
            test_qs[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(test_qs, doseq=True)))
            resp = await self.fetch(test_url)
            if resp and expected in resp.text():
                self.add_finding(
                    title=f"Server-Side Template Injection (SSTI) — {label}",
                    severity="CRITICAL",
                    category="RCE",
                    description=(
                        f"Template expression '{payload}' evaluated to '{expected}', confirming {label}. "
                        "SSTI allows attackers to execute arbitrary code on the server, "
                        "leading to full Remote Code Execution."
                    ),
                    evidence=f"Payload: {payload} → Response contains: {expected}",
                    fix=(
                        "Never pass user input directly to template engines. "
                        "Use sandboxed template environments. In Jinja2: use autoescape=True. "
                        "Validate and sanitise all inputs before template rendering."
                    ),
                    cvss_score=10.0,
                )
                return

    async def _check_rce_endpoints(self):
        for path in self.RCE_ENDPOINTS:
            resp = await self.fetch(self.url + path)
            if resp and resp.status in (200, 405):
                self.add_finding(
                    title=f"Potentially Dangerous Endpoint Exposed: {path}",
                    severity="CRITICAL" if resp.status == 200 else "HIGH",
                    category="RCE",
                    description=(
                        f"Endpoint '{path}' responded with HTTP {resp.status}. "
                        "Execution/eval endpoints should never be publicly accessible "
                        "as they may allow arbitrary code execution."
                    ),
                    evidence=f"GET {self.url + path} → HTTP {resp.status}",
                    fix=(
                        "Remove debug/eval endpoints from production. "
                        "If needed for internal use, restrict to localhost or authenticated internal networks only."
                    ),
                    cvss_score=10.0 if resp.status == 200 else 8.0,
                )
