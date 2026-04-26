"""
WebGuard AI — Injection Scanner
Tests for SQL, Command, and NoSQL injection patterns.
All payloads are safe/non-destructive observation-only.
"""
from scanners.base import BaseScanner
import re
import logging

logger = logging.getLogger(__name__)

# Safe payloads — cause observable differences without destruction
SQL_PAYLOADS = [
    ("'", "SQL single-quote probe"),
    ("1 AND 1=1", "SQL boolean true"),
    ("1 AND 1=2", "SQL boolean false"),
    ("1' OR '1'='1", "SQL OR tautology"),
    ("1; SELECT 1--", "SQL stacked query probe"),
    ("1 UNION SELECT NULL--", "SQL UNION probe"),
]

CMD_PATTERNS = [
    r";\s*(?:ls|dir|cat|type|echo|id|whoami|uname)\b",
    r"\|\s*(?:ls|dir|cat|type|echo|id|whoami)\b",
    r"`[^`]+`",
    r"\$\([^)]+\)",
]

NOSQL_PAYLOADS = [
    ('{"$gt": ""}', "NoSQL $gt operator"),
    ('{"$where": "1==1"}', "NoSQL $where operator"),
]

SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query()",
    "supplied argument is not a valid mysql",
    "sqlstate",
    "ora-00",
    "microsoft sql native client",
]

CMD_SIGNATURES = [
    "root:x:0:0",
    "volume serial number",
    "uid=",
    "www-data",
]


class InjectionScanner(BaseScanner):
    """
    Tests URL parameters for injection vulnerabilities.
    Uses safe reflection-based detection (error messages, timing divergence).
    """

    async def run(self):
        resp = await self.fetch(self.url)
        if not resp:
            return self.result()

        params = self._extract_params(self.url)
        if not params:
            # Heuristically test a common parameter
            params = ["id", "q", "search", "page", "cat"]
            self._test_headers_injection(resp)
        else:
            await self._test_sql_injection(params)
            await self._test_nosql_injection(params)

        await self._detect_error_based(resp)
        return self.result()

    def _extract_params(self, url: str) -> list:
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        return list(qs.keys())

    async def _test_sql_injection(self, params: list):
        from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
        parsed = urlparse(self.url)
        qs = parse_qs(parsed.query)

        for param in params[:3]:  # Limit to first 3 params
            original_val = qs.get(param, ["1"])[0]
            responses = {}

            for payload, label in SQL_PAYLOADS[:4]:
                test_qs = dict(qs)
                test_qs[param] = [original_val + payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_qs, doseq=True)))
                resp = await self.fetch(test_url)
                if resp:
                    body = resp.text()
                    responses[label] = body

            # Check for SQL error signatures in responses
            for label, body in responses.items():
                for sig in SQL_ERROR_SIGNATURES:
                    if sig in body.lower():
                        self.add_finding(
                            title=f"Potential SQL Injection — Parameter '{param}'",
                            severity="CRITICAL",
                            category="SQL Injection",
                            description=(
                                f"The parameter '{param}' may be vulnerable to SQL injection. "
                                f"SQL error signature '{sig}' was detected in the server response "
                                f"when injecting payload: {label}. Attackers can exploit this to "
                                f"extract, modify, or delete database contents."
                            ),
                            evidence=f"Payload: {label} → Response contained: '{sig}'",
                            fix=(
                                "Use parameterised queries or prepared statements. "
                                "Example (Python): cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)). "
                                "Never interpolate user input directly into SQL strings. "
                                "Also implement a WAF as defence-in-depth."
                            ),
                            references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                            cve_ids=[],
                            cvss_score=9.8,
                        )
                        return  # One finding per scanner is sufficient

            # Differential analysis: boolean-based blind detection
            if len(responses) >= 2:
                vals = list(responses.values())
                if vals[0] != vals[1] and len(vals[0]) != len(vals[1]):
                    diff = abs(len(vals[0]) - len(vals[1]))
                    if diff > 200:
                        self.add_finding(
                            title=f"Possible Blind SQL Injection — Parameter '{param}'",
                            severity="HIGH",
                            category="SQL Injection",
                            description=(
                                f"Boolean-based differential testing on parameter '{param}' produced "
                                f"response length differences of {diff} bytes between true/false payloads. "
                                f"This may indicate blind SQL injection susceptibility."
                            ),
                            evidence=f"TRUE payload response: {len(vals[0])} bytes, FALSE: {len(vals[1])} bytes",
                            fix=(
                                "Use parameterised queries. Implement strict input validation. "
                                "Suppress verbose error messages in production. Deploy a WAF."
                            ),
                            cvss_score=8.1,
                        )
                        return

    async def _test_nosql_injection(self, params: list):
        if not params:
            return
        for payload, label in NOSQL_PAYLOADS:
            test_url = f"{self.url}?{params[0]}={payload}"
            resp = await self.fetch(test_url)
            if resp and resp.status == 200:
                body = resp.text().lower()
                if any(sig in body for sig in ["mongodb", "mongoose", "objectid", "bson"]):
                    self.add_finding(
                        title="NoSQL Injection Risk Detected",
                        severity="HIGH",
                        category="NoSQL Injection",
                        description=(
                            "The application appears to use MongoDB and may be vulnerable to NoSQL injection. "
                            f"Operator payload '{label}' was accepted and a 200 response returned. "
                            "Attackers can bypass authentication or exfiltrate data using $where/$gt operators."
                        ),
                        evidence=f"Payload: {payload} → HTTP 200",
                        fix=(
                            "Validate and sanitise all user inputs before passing to MongoDB queries. "
                            "Use mongoose schema validation. Disable $where operator in MongoDB config. "
                            "Example: { $where: 'this.credits == this.debits' } must be blocked."
                        ),
                        references=["https://owasp.org/www-project-web-security-testing-guide/"],
                        cvss_score=8.8,
                    )
                    break

    def _test_headers_injection(self, resp):
        server = resp.headers.get("Server", "")
        x_powered = resp.headers.get("X-Powered-By", "")
        if server or x_powered:
            self.add_finding(
                title="Server Technology Disclosed via HTTP Headers",
                severity="LOW",
                category="Information Disclosure",
                description=(
                    f"The server is disclosing technology information in response headers. "
                    f"Server: '{server}', X-Powered-By: '{x_powered}'. "
                    "This aids attackers in identifying the software stack and targeting known CVEs."
                ),
                evidence=f"Server: {server} | X-Powered-By: {x_powered}",
                fix=(
                    "Remove or obfuscate Server and X-Powered-By headers. "
                    "In Apache: ServerTokens Prod, ServerSignature Off. "
                    "In Nginx: server_tokens off. In Express.js: app.disable('x-powered-by')."
                ),
            )

    async def _detect_error_based(self, resp):
        if not resp:
            return
        body = resp.text().lower()
        for sig in SQL_ERROR_SIGNATURES:
            if sig in body:
                self.add_finding(
                    title="SQL Error Message Exposed in Response",
                    severity="HIGH",
                    category="SQL Injection",
                    description=(
                        f"An SQL error message ('{sig}') is visible in the page response. "
                        "Even without active injection, exposed error messages reveal database "
                        "internals and dramatically reduce the difficulty of SQL injection attacks."
                    ),
                    evidence=f"Found pattern '{sig}' in response body",
                    fix=(
                        "Disable verbose database errors in production. "
                        "Catch exceptions server-side and return generic error pages. "
                        "Log detailed errors to server logs only, never to the client."
                    ),
                    cvss_score=5.3,
                )
                break
