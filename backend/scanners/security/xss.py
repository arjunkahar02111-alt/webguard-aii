"""
WebGuard AI — Security Scanner Modules
XSS, CSRF, Headers, SSL/TLS, CORS, Cookies, Auth, IDOR, 
Open Redirect, SSRF, Directory Traversal, Clickjacking,
File Upload, API Security, Dependencies, Subdomain, DNS
"""
from scanners.base import BaseScanner
import re, socket, ssl, logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# XSS Scanner
# ─────────────────────────────────────────────────────────────────────────────
class XSSScanner(BaseScanner):
    SAFE_XSS_PROBES = [
        "<script>/*xss-probe*/</script>",
        "\"'><img src=x>",
        "javascript:void(0)",
        "<svg/onload=1>",
    ]

    async def run(self):
        resp = await self.fetch(self.url)
        if not resp:
            return self.result()

        body = resp.text()
        csp = resp.headers.get("Content-Security-Policy", "")

        # Check for reflected probe in response (safe — we only check reflection)
        from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
        parsed = urlparse(self.url)
        qs = parse_qs(parsed.query)
        if qs:
            param = list(qs.keys())[0]
            probe = self.SAFE_XSS_PROBES[0]
            test_qs = dict(qs)
            test_qs[param] = [probe]
            test_url = urlunparse(parsed._replace(query=urlencode(test_qs, doseq=True)))
            xss_resp = await self.fetch(test_url)
            if xss_resp and probe in xss_resp.text():
                self.add_finding(
                    title=f"Reflected XSS — Parameter '{param}'",
                    severity="CRITICAL",
                    category="XSS",
                    description=(
                        f"Parameter '{param}' reflects user input unsanitised in the response. "
                        "An attacker can craft a URL containing malicious JavaScript that executes "
                        "in victims' browsers, enabling session hijacking and credential theft."
                    ),
                    evidence=f"Probe '<script>/*xss-probe*/</script>' reflected verbatim in response",
                    fix=(
                        "HTML-encode all user input before rendering: use htmlspecialchars() in PHP, "
                        "{{ }} in Django/Jinja2 (auto-escaped), or DOMPurify in JS. "
                        "Add a strong Content-Security-Policy header."
                    ),
                    cvss_score=9.3,
                )

        # DOM-based XSS indicators
        dom_sinks = ["document.write(", "innerHTML", "eval(", "setTimeout(", "document.location"]
        found_sinks = [s for s in dom_sinks if s in body]
        if found_sinks and not csp:
            self.add_finding(
                title="DOM-Based XSS Risk — Dangerous Sinks Detected",
                severity="HIGH",
                category="XSS",
                description=(
                    f"Dangerous DOM sink(s) found in page source: {', '.join(found_sinks)}. "
                    "Without a Content-Security-Policy, these can be exploited for DOM-based XSS "
                    "where attacker-controlled data reaches these sinks."
                ),
                evidence=f"Sinks found: {', '.join(found_sinks)}",
                fix=(
                    "Avoid passing user-controlled data to dangerous sinks. "
                    "Use textContent instead of innerHTML. "
                    "Implement CSP: script-src 'self' to block inline scripts."
                ),
                cvss_score=7.5,
            )

        if not csp:
            self.add_finding(
                title="Missing Content-Security-Policy Header",
                severity="MEDIUM",
                category="XSS",
                description=(
                    "No Content-Security-Policy header is set. CSP provides a powerful layer "
                    "of defence against XSS attacks by restricting the sources from which "
                    "scripts, styles and other resources can be loaded."
                ),
                evidence="Header 'Content-Security-Policy' absent from response",
                fix=(
                    "Add CSP: Content-Security-Policy: default-src 'self'; script-src 'self'; "
                    "object-src 'none'; base-uri 'self'. "
                    "Start with report-only mode to avoid breaking changes."
                ),
            )

        return self.result()


# ─────────────────────────────────────────────────────────────────────────────
# CSRF Scanner
# ─────────────────────────────────────────────────────────────────────────────
class CSRFScanner(BaseScanner):
    async def run(self):
        resp = await self.fetch(self.url)
        if not resp:
            return self.result()
        body = resp.text()

        # Look for forms without CSRF tokens
        forms = re.findall(r'<form[^>]*>.*?</form>', body, re.DOTALL | re.IGNORECASE)
        csrf_token_patterns = [
            r'csrf', r'_token', r'authenticity_token', r'nonce', r'__RequestVerificationToken'
        ]

        for form in forms:
            method = re.search(r'method=["\']?(\w+)', form, re.IGNORECASE)
            if method and method.group(1).upper() == "POST":
                has_token = any(re.search(p, form, re.IGNORECASE) for p in csrf_token_patterns)
                if not has_token:
                    self.add_finding(
                        title="CSRF Token Missing in POST Form",
                        severity="HIGH",
                        category="CSRF",
                        description=(
                            "A POST form was found without a CSRF token. "
                            "Cross-Site Request Forgery allows attackers to trick authenticated users "
                            "into submitting unintended requests, potentially changing account settings "
                            "or performing financial transactions."
                        ),
                        evidence=f"POST form found without CSRF token: {form[:200]}...",
                        fix=(
                            "Add synchroniser token pattern: generate a cryptographically random token "
                            "per session, embed it as a hidden field, and validate server-side. "
                            "In Django: use {% csrf_token %}. In Flask: use Flask-WTF. "
                            "Also set SameSite=Strict on session cookies."
                        ),
                        references=["https://owasp.org/www-community/attacks/csrf"],
                        cvss_score=8.8,
                    )
                    break

        # Check SameSite cookie attribute
        set_cookie = resp.headers.get("Set-Cookie", "")
        if set_cookie and "samesite" not in set_cookie.lower():
            self.add_finding(
                title="Session Cookie Missing SameSite Attribute",
                severity="MEDIUM",
                category="CSRF",
                description=(
                    "Session cookies lack the SameSite attribute, making them vulnerable to "
                    "cross-site request forgery. SameSite=Strict prevents cookies from being "
                    "sent with cross-site requests."
                ),
                evidence=f"Set-Cookie: {set_cookie[:150]}",
                fix="Add SameSite=Strict (or Lax) to all session cookies: Set-Cookie: session=...; SameSite=Strict; Secure",
            )

        return self.result()


# ─────────────────────────────────────────────────────────────────────────────
# Security Headers Scanner
# ─────────────────────────────────────────────────────────────────────────────
class HeadersScanner(BaseScanner):
    REQUIRED_HEADERS = {
        "Strict-Transport-Security": ("HIGH", "HSTS Missing",
            "Without HSTS, browsers may connect via HTTP, enabling downgrade attacks.",
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"),
        "X-Content-Type-Options": ("MEDIUM", "X-Content-Type-Options Missing",
            "Without nosniff, browsers may MIME-sniff responses, enabling XSS via file uploads.",
            "Add: X-Content-Type-Options: nosniff"),
        "X-Frame-Options": ("MEDIUM", "Clickjacking Protection Missing",
            "Without X-Frame-Options, the page can be embedded in iframes for clickjacking attacks.",
            "Add: X-Frame-Options: DENY or SAMEORIGIN"),
        "Referrer-Policy": ("LOW", "Referrer-Policy Missing",
            "Without Referrer-Policy, sensitive URLs may leak to third-party sites.",
            "Add: Referrer-Policy: strict-origin-when-cross-origin"),
        "Permissions-Policy": ("LOW", "Permissions-Policy Missing",
            "Without Permissions-Policy, the site grants unnecessary browser feature access.",
            "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"),
    }

    async def run(self):
        resp = await self.fetch(self.url)
        if not resp:
            return self.result()

        for header, (severity, title, desc, fix) in self.REQUIRED_HEADERS.items():
            if header not in resp.headers:
                self.add_finding(
                    title=title,
                    severity=severity,
                    category="Security Headers",
                    description=desc,
                    evidence=f"Header '{header}' not present in HTTP response",
                    fix=fix,
                )

        # Check for dangerous headers
        if "X-Powered-By" in resp.headers:
            self.add_finding(
                title="Technology Disclosure via X-Powered-By Header",
                severity="LOW",
                category="Information Disclosure",
                description="The X-Powered-By header reveals server technology, aiding attacker reconnaissance.",
                evidence=f"X-Powered-By: {resp.headers['X-Powered-By']}",
                fix="Remove: In Express.js: app.disable('x-powered-by'). In PHP: expose_php = Off",
            )

        return {"findings": self.findings, "headers": dict(resp.headers)}


# ─────────────────────────────────────────────────────────────────────────────
# SSL/TLS Scanner
# ─────────────────────────────────────────────────────────────────────────────
class SSLScanner(BaseScanner):
    async def run(self):
        from urllib.parse import urlparse
        parsed = urlparse(self.url)

        # Check HTTP vs HTTPS
        if parsed.scheme == "http":
            self.add_finding(
                title="Site Served Over HTTP (No Encryption)",
                severity="CRITICAL",
                category="SSL/TLS",
                description=(
                    "The site is served over plain HTTP without TLS encryption. "
                    "All data transmitted between users and the server is visible to "
                    "network attackers (MITM), including passwords and session tokens."
                ),
                evidence=f"URL scheme is HTTP: {self.url}",
                fix=(
                    "Obtain and install a TLS certificate (Let's Encrypt is free). "
                    "Redirect all HTTP → HTTPS. Add HSTS header. "
                    "Nginx: listen 443 ssl; with ssl_certificate /path/to/cert.pem"
                ),
                cvss_score=9.1,
            )
            return self.result()

        hostname = parsed.hostname
        port = parsed.port or 443
        ssl_info = await self._check_ssl(hostname, port)
        if ssl_info:
            self._analyse_ssl(ssl_info)

        return self.result()

    async def _check_ssl(self, hostname: str, port: int) -> dict:
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            ctx = ssl.create_default_context()

            def _get_cert():
                with socket.create_connection((hostname, port), timeout=10) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        version = ssock.version()
                        cipher = ssock.cipher()
                        return {"cert": cert, "version": version, "cipher": cipher}

            return await loop.run_in_executor(None, _get_cert)
        except ssl.SSLError as e:
            self.add_finding(
                title="SSL Certificate Error",
                severity="CRITICAL",
                category="SSL/TLS",
                description=f"SSL handshake failed: {e}. Users will see certificate warnings.",
                evidence=str(e),
                fix="Install a valid, trusted TLS certificate. Check certificate chain completeness.",
                cvss_score=9.0,
            )
        except Exception as e:
            logger.debug(f"SSL check error: {e}")
        return None

    def _analyse_ssl(self, ssl_info: dict):
        cert = ssl_info.get("cert", {})
        version = ssl_info.get("version", "")
        cipher = ssl_info.get("cipher", ("", "", 0))

        # Check protocol version
        if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
            self.add_finding(
                title=f"Deprecated TLS Protocol: {version}",
                severity="HIGH",
                category="SSL/TLS",
                description=(
                    f"The server supports {version}, which has known cryptographic weaknesses "
                    "and is deprecated by modern standards. POODLE and BEAST attacks target old protocols."
                ),
                evidence=f"Negotiated protocol: {version}",
                fix="Disable TLS 1.0 and 1.1. Support only TLS 1.2 and TLS 1.3. "
                    "In Nginx: ssl_protocols TLSv1.2 TLSv1.3;",
                cvss_score=7.4,
            )

        # Check certificate expiry
        if "notAfter" in cert:
            expire_str = cert["notAfter"]
            try:
                expire_dt = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (expire_dt - datetime.utcnow()).days
                if days_left < 30:
                    self.add_finding(
                        title=f"SSL Certificate Expiring Soon ({days_left} days)",
                        severity="HIGH" if days_left < 7 else "MEDIUM",
                        category="SSL/TLS",
                        description=f"The SSL certificate expires in {days_left} days. Expired certs cause browser warnings and break HTTPS.",
                        evidence=f"Certificate notAfter: {expire_str}",
                        fix="Renew the certificate immediately. Use Let's Encrypt with auto-renewal via certbot.",
                    )
            except Exception:
                pass

        # Weak cipher check
        cipher_name = cipher[0] if cipher else ""
        if any(w in cipher_name for w in ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon"]):
            self.add_finding(
                title=f"Weak Cipher Suite: {cipher_name}",
                severity="HIGH",
                category="SSL/TLS",
                description=f"The server negotiated a weak cipher suite: {cipher_name}. Weak ciphers can be cracked, exposing encrypted traffic.",
                evidence=f"Cipher: {cipher_name}, Key size: {cipher[2]} bits",
                fix="Disable weak ciphers. Use: ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256; in Nginx.",
                cvss_score=7.5,
            )

        return self.result()


# ─────────────────────────────────────────────────────────────────────────────
# CORS Scanner
# ─────────────────────────────────────────────────────────────────────────────
class CORSScanner(BaseScanner):
    async def run(self):
        resp = await self.fetch(
            self.url,
            headers={"Origin": "https://evil.example.com"}
        )
        if not resp:
            return self.result()

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*":
            self.add_finding(
                title="CORS Wildcard Origin Allowed",
                severity="MEDIUM",
                category="CORS Misconfiguration",
                description=(
                    "The server allows requests from any origin (Access-Control-Allow-Origin: *). "
                    "While not dangerous alone, combined with sensitive endpoints this can leak data."
                ),
                evidence=f"Access-Control-Allow-Origin: {acao}",
                fix="Restrict CORS to specific trusted origins. Maintain an allowlist of permitted origins.",
            )

        if acao == "https://evil.example.com":
            sev = "CRITICAL" if acac.lower() == "true" else "HIGH"
            self.add_finding(
                title="CORS Origin Reflection (Arbitrary Origin Trusted)",
                severity=sev,
                category="CORS Misconfiguration",
                description=(
                    "The server reflects the request Origin header back, trusting any origin. "
                    + ("With Allow-Credentials: true, attackers can steal authenticated data." if sev == "CRITICAL"
                       else "Attackers can read cross-origin responses.")
                ),
                evidence=f"Sent Origin: https://evil.example.com → ACAO: {acao}, ACAC: {acac}",
                fix=(
                    "Validate Origin against a strict allowlist. Never reflect the Origin header blindly. "
                    "Example: ALLOWED = {'https://app.example.com'}; if origin in ALLOWED: set_header(origin)"
                ),
                cvss_score=9.8 if sev == "CRITICAL" else 7.5,
            )

        return self.result()


# ─────────────────────────────────────────────────────────────────────────────
# Cookie Scanner
# ─────────────────────────────────────────────────────────────────────────────
class CookieScanner(BaseScanner):
    async def run(self):
        resp = await self.fetch(self.url)
        if not resp:
            return self.result()

        set_cookie = resp.headers.get("Set-Cookie", "")
        if not set_cookie:
            return self.result()

        cookie_lower = set_cookie.lower()
        is_session_cookie = any(k in cookie_lower for k in ["session", "sessionid", "sess", "auth", "token"])

        if "httponly" not in cookie_lower:
            self.add_finding(
                title="Session Cookie Missing HttpOnly Flag",
                severity="HIGH" if is_session_cookie else "MEDIUM",
                category="Cookie Security",
                description=(
                    "Cookie(s) lack the HttpOnly flag, making them accessible via JavaScript. "
                    "If XSS exists, attackers can steal these cookies to hijack sessions."
                ),
                evidence=f"Set-Cookie: {set_cookie[:200]}",
                fix="Add HttpOnly flag to all sensitive cookies: Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict",
            )

        if "secure" not in cookie_lower:
            self.add_finding(
                title="Session Cookie Missing Secure Flag",
                severity="HIGH" if is_session_cookie else "MEDIUM",
                category="Cookie Security",
                description=(
                    "Cookie(s) lack the Secure flag. Without it, cookies are transmitted over "
                    "unencrypted HTTP connections, exposing them to MITM attackers."
                ),
                evidence=f"Set-Cookie: {set_cookie[:200]}",
                fix="Add Secure flag: Set-Cookie: session=...; Secure; HttpOnly",
            )

        if "samesite" not in cookie_lower:
            self.add_finding(
                title="Session Cookie Missing SameSite Attribute",
                severity="MEDIUM",
                category="Cookie Security",
                description="Without SameSite, cookies are sent with cross-site requests, enabling CSRF attacks.",
                evidence=f"Set-Cookie: {set_cookie[:200]}",
                fix="Add SameSite=Strict (preferred) or Lax: Set-Cookie: session=...; SameSite=Strict",
            )

        return self.result()


# ─────────────────────────────────────────────────────────────────────────────
# Auth Scanner
# ─────────────────────────────────────────────────────────────────────────────
class AuthScanner(BaseScanner):
    LOGIN_PATHS = ["/login", "/signin", "/admin", "/wp-login.php", "/user/login", "/auth"]
    ADMIN_PATHS = ["/admin", "/admin/", "/administrator", "/wp-admin", "/dashboard", "/manage"]

    async def run(self):
        for path in self.LOGIN_PATHS[:3]:
            resp = await self.fetch(self.url + path)
            if resp and resp.status == 200:
                body = resp.text().lower()
                self._check_login_page(body, path)
                break

        await self._check_default_credentials()
        await self._check_admin_exposure()
        return self.result()

    def _check_login_page(self, body: str, path: str):
        if "autocomplete" not in body or "autocomplete=\"off\"" not in body:
            self.add_finding(
                title="Password Field Allows Browser Autocomplete",
                severity="LOW",
                category="Authentication",
                description="Login form doesn't disable autocomplete on password field, risking credential storage on shared computers.",
                evidence=f"autocomplete='off' not found in {path}",
                fix="Add autocomplete='off' to password fields and autocomplete='new-password' where appropriate.",
            )

        if "captcha" not in body and "recaptcha" not in body and "hcaptcha" not in body:
            self.add_finding(
                title="No CAPTCHA on Login Form — Brute Force Risk",
                severity="MEDIUM",
                category="Authentication",
                description=(
                    f"Login at {path} has no CAPTCHA or visible bot protection. "
                    "Attackers can automate credential stuffing and brute-force attacks."
                ),
                evidence=f"No captcha/recaptcha detected at {path}",
                fix=(
                    "Implement CAPTCHA (Google reCAPTCHA v3 or hCaptcha). "
                    "Also add account lockout after N failed attempts and rate limiting per IP."
                ),
            )

        if "2fa" not in body and "two-factor" not in body and "totp" not in body and "otp" not in body:
            self.add_finding(
                title="No Two-Factor Authentication Detected",
                severity="MEDIUM",
                category="Authentication",
                description="No 2FA indicators found. Without 2FA, compromised passwords give full account access.",
                evidence=f"No 2FA indicators at {path}",
                fix="Implement TOTP-based 2FA (e.g., using speakeasy/pyotp). Consider WebAuthn for phishing-resistant auth.",
            )

    async def _check_default_credentials(self):
        for path in self.ADMIN_PATHS[:2]:
            resp = await self.fetch(self.url + path, allow_redirects=False)
            if resp and resp.status == 200:
                body = resp.text().lower()
                if "admin" in body or "login" in body or "password" in body:
                    self.add_finding(
                        title=f"Admin Panel Publicly Accessible: {path}",
                        severity="HIGH",
                        category="Broken Access Control",
                        description=(
                            f"The admin panel at {path} is publicly accessible without authentication challenge. "
                            "This significantly increases attack surface for credential brute-forcing."
                        ),
                        evidence=f"GET {self.url + path} → HTTP 200",
                        fix=(
                            "Restrict admin paths to specific IP ranges. "
                            "Implement multi-factor authentication. "
                            "Use non-default admin paths (security through obscurity as defence-in-depth)."
                        ),
                        cvss_score=8.2,
                    )

    async def _check_admin_exposure(self):
        resp = await self.fetch(self.url + "/robots.txt")
        if resp and resp.status == 200:
            body = resp.text()
            if "admin" in body.lower() or "private" in body.lower():
                self.add_finding(
                    title="Sensitive Paths Disclosed in robots.txt",
                    severity="LOW",
                    category="Information Disclosure",
                    description="robots.txt reveals sensitive paths (admin, private areas) that attackers can directly target.",
                    evidence=f"Sensitive paths found in robots.txt: {body[:300]}",
                    fix="Remove sensitive path disclosures from robots.txt. Rely on proper access control, not obscurity alone.",
                )


# ─────────────────────────────────────────────────────────────────────────────
# IDOR Scanner
# ─────────────────────────────────────────────────────────────────────────────
class IDORScanner(BaseScanner):
    async def run(self):
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(self.url)
        qs = parse_qs(parsed.query)

        id_params = [k for k in qs if any(x in k.lower() for x in ["id", "user", "account", "profile", "order"])]
        for param in id_params[:2]:
            original = qs[param][0]
            if original.isdigit():
                modified = str(int(original) + 1)
                test_qs = dict(qs)
                test_qs[param] = [modified]
                test_url = urlunparse(parsed._replace(query=urlencode(test_qs, doseq=True)))
                resp1 = await self.fetch(self.url)
                resp2 = await self.fetch(test_url)
                if resp1 and resp2 and resp2.status == 200:
                    self.add_finding(
                        title=f"Potential IDOR — Parameter '{param}'",
                        severity="HIGH",
                        category="IDOR",
                        description=(
                            f"Incrementing the '{param}' parameter returned a 200 response, "
                            "suggesting object references may not be validated against the current user. "
                            "Attackers can enumerate IDs to access other users' data."
                        ),
                        evidence=f"Original: {param}={original} (200), Modified: {param}={modified} (200)",
                        fix=(
                            "Implement object-level authorisation checks server-side for every request. "
                            "Use UUIDs instead of sequential IDs. "
                            "Verify that the authenticated user owns the requested resource."
                        ),
                        cvss_score=8.1,
                    )
        return self.result()


# ─────────────────────────────────────────────────────────────────────────────
# Open Redirect Scanner
# ─────────────────────────────────────────────────────────────────────────────
class OpenRedirectScanner(BaseScanner):
    REDIRECT_PARAMS = ["redirect", "redirect_to", "next", "url", "return", "returnTo", "goto", "destination"]
    SAFE_PROBE = "https://example-probe.webguard.ai"

    async def run(self):
        from urllib.parse import urlparse, urlencode
        parsed = urlparse(self.url)
        for param in self.REDIRECT_PARAMS:
            test_url = f"{self.url}?{param}={self.SAFE_PROBE}"
            resp = await self.fetch(test_url, allow_redirects=False)
            if resp and resp.status in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if "example-probe.webguard.ai" in location:
                    self.add_finding(
                        title=f"Open Redirect — Parameter '{param}'",
                        severity="MEDIUM",
                        category="Open Redirect",
                        description=(
                            f"Parameter '{param}' allows redirecting to arbitrary external URLs. "
                            "Attackers use open redirects in phishing: legitimate-looking URLs that "
                            "redirect to malicious sites, bypassing URL reputation filters."
                        ),
                        evidence=f"?{param}=https://evil.com → Location: {location}",
                        fix=(
                            "Validate redirect URLs against an allowlist of trusted domains. "
                            "Use relative paths for redirects. "
                            "If external redirects needed, use an intermediate warning page."
                        ),
                        cvss_score=6.1,
                    )
                    break

        return self.result()


# ─────────────────────────────────────────────────────────────────────────────
# SSRF Scanner
# ─────────────────────────────────────────────────────────────────────────────
class SSRFScanner(BaseScanner):
    URL_PARAMS = ["url", "image", "file", "src", "source", "path", "fetch", "load", "proxy"]

    async def run(self):
        from urllib.parse import urlparse
        parsed = urlparse(self.url)
        qs_string = parsed.query

        found_params = [p for p in self.URL_PARAMS if p in qs_string]
        if found_params:
            self.add_finding(
                title=f"SSRF Risk — URL Parameter(s) Detected: {', '.join(found_params)}",
                severity="HIGH",
                category="SSRF",
                description=(
                    f"URL-like parameters ({', '.join(found_params)}) were detected in the query string. "
                    "If the server fetches these URLs without validation, attackers can probe internal "
                    "services (AWS metadata, internal APIs) or perform port scanning."
                ),
                evidence=f"Detected URL parameters in query: {qs_string[:200]}",
                fix=(
                    "Validate all URL parameters against an allowlist of permitted schemes and hosts. "
                    "Block requests to private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.x.x). "
                    "Use a dedicated fetcher with egress restrictions."
                ),
                cvss_score=9.0,
            )

        return self.result()


# ─────────────────────────────────────────────────────────────────────────────
# Directory Traversal Scanner
# ─────────────────────────────────────────────────────────────────────────────
class TraversalScanner(BaseScanner):
    TRAVERSAL_PROBES = ["../", "..%2F", "....//", "%2e%2e%2f"]
    TRAVERSAL_PARAMS = ["file", "path", "page", "include", "template", "dir", "folder", "doc"]

    async def run(self):
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(self.url)
        qs = parse_qs(parsed.query)

        vuln_params = [k for k in qs if k.lower() in self.TRAVERSAL_PARAMS]
        for param in vuln_params[:2]:
            probe = "../" * 5 + "etc/passwd"
            test_qs = dict(qs)
            test_qs[param] = [probe]
            test_url = urlunparse(parsed._replace(query=urlencode(test_qs, doseq=True)))
            resp = await self.fetch(test_url)
            if resp and "root:" in resp.text():
                self.add_finding(
                    title=f"Directory Traversal — Parameter '{param}'",
                    severity="CRITICAL",
                    category="Directory Traversal",
                    description=(
                        f"Path traversal via '{param}' succeeded: /etc/passwd content detected. "
                        "Attackers can read arbitrary files from the server filesystem."
                    ),
                    evidence=f"?{param}=../../../../../etc/passwd → /etc/passwd content in response",
                    fix=(
                        "Validate file paths by resolving and checking against a base directory. "
                        "Use realpath() and verify prefix. Never allow user input to directly specify file paths."
                    ),
                    cvss_score=9.8,
                )
            else:
                self.add_finding(
                    title=f"File Inclusion Parameter Detected — Traversal Risk: '{param}'",
                    severity="MEDIUM",
                    category="Directory Traversal",
                    description=(
                        f"Parameter '{param}' appears to handle file paths. "
                        "Even if not immediately exploitable, file inclusion parameters require strict validation."
                    ),
                    evidence=f"File-like parameter '{param}' found in URL",
                    fix="Implement strict allowlist of permitted files. Never use user input to construct file system paths.",
                )
        return self.result()


# ─────────────────────────────────────────────────────────────────────────────
# Clickjacking Scanner
# ─────────────────────────────────────────────────────────────────────────────
class ClickjackingScanner(BaseScanner):
    async def run(self):
        resp = await self.fetch(self.url)
        if not resp:
            return self.result()

        xfo = resp.headers.get("X-Frame-Options", "")
        csp = resp.headers.get("Content-Security-Policy", "")
        frame_ancestors = "frame-ancestors" in csp.lower()

        if not xfo and not frame_ancestors:
            self.add_finding(
                title="Clickjacking Protection Missing",
                severity="MEDIUM",
                category="Clickjacking",
                description=(
                    "Neither X-Frame-Options nor CSP frame-ancestors is set. "
                    "The page can be embedded in an attacker's iframe, enabling clickjacking — "
                    "tricking users into clicking buttons/links on the victim site invisibly."
                ),
                evidence="X-Frame-Options absent, CSP frame-ancestors absent",
                fix=(
                    "Add: X-Frame-Options: DENY "
                    "Or CSP: Content-Security-Policy: frame-ancestors 'none'. "
                    "Prefer CSP frame-ancestors as it's more flexible and spec-compliant."
                ),
                cvss_score=6.5,
            )
        elif xfo.upper() not in ("DENY", "SAMEORIGIN"):
            self.add_finding(
                title=f"Weak X-Frame-Options Value: '{xfo}'",
                severity="LOW",
                category="Clickjacking",
                description=f"X-Frame-Options is set to '{xfo}' which may not provide adequate protection. DENY or SAMEORIGIN are recommended.",
                evidence=f"X-Frame-Options: {xfo}",
                fix="Change to X-Frame-Options: DENY (most restrictive) or SAMEORIGIN.",
            )
        return self.result()


# ─────────────────────────────────────────────────────────────────────────────
# File Upload Scanner
# ─────────────────────────────────────────────────────────────────────────────
class FileUploadScanner(BaseScanner):
    UPLOAD_PATHS = ["/upload", "/api/upload", "/file/upload", "/media/upload", "/assets/upload"]

    async def run(self):
        body_main = ""
        resp = await self.fetch(self.url)
        if resp:
            body_main = resp.text()

        # Check main page for file upload forms
        if 'type="file"' in body_main or "multipart/form-data" in body_main:
            self.add_finding(
                title="File Upload Endpoint Detected — Validation Required",
                severity="MEDIUM",
                category="File Upload",
                description=(
                    "A file upload form was detected. Without strict server-side validation "
                    "of file type, content, and size, attackers may upload webshells, "
                    "malware, or excessively large files."
                ),
                evidence="type='file' or multipart/form-data found in page source",
                fix=(
                    "Validate: (1) file extension whitelist, (2) MIME type via magic bytes, "
                    "(3) file size limit, (4) scan with antivirus. "
                    "Store uploads outside webroot. Rename files server-side. "
                    "Serve with Content-Disposition: attachment."
                ),
                cvss_score=8.8,
            )

        # Check known upload endpoints
        for path in self.UPLOAD_PATHS[:3]:
            resp = await self.fetch(self.url + path, allow_redirects=False)
            if resp and resp.status in (200, 405):
                body_text = resp.text().lower()
                if "upload" in body_text or "multipart/form-data" in body_text or "file" in body_text or resp.status == 405:
                    self.add_finding(
                        title=f"File Upload Endpoint Found: {path}",
                        severity="HIGH",
                        category="File Upload",
                        description=(
                            f"Upload endpoint at {path} responded. "
                            "Without file type validation, attackers can upload executable files "
                            "leading to Remote Code Execution."
                        ),
                        evidence=f"GET/POST {self.url + path} → HTTP {resp.status}",
                        fix="Implement strict file type validation, content scanning, and store files outside webroot.",
                        cvss_score=9.0,
                    )
                    break

        return self.result()


# ─────────────────────────────────────────────────────────────────────────────
# API Security Scanner
# ─────────────────────────────────────────────────────────────────────────────
class APISecurityScanner(BaseScanner):
    API_PATHS = ["/api", "/api/v1", "/api/v2", "/graphql", "/swagger", "/openapi.json", "/api-docs"]

    async def run(self):
        for path in self.API_PATHS:
            resp = await self.fetch(self.url + path)
            if not resp or resp.status not in (200, 401, 403):
                continue

            if resp.status == 200:
                body = resp.text().lower()
                content_type = resp.headers.get("Content-Type", "").lower()
                # Check for unauthenticated API access
                if "application/json" in content_type and any(k in body for k in ['"data"', '"results"', '"users"', '"items"', '{"id"']):
                    self.add_finding(
                        title=f"Unauthenticated API Endpoint: {path}",
                        severity="HIGH",
                        category="API Security",
                        description=(
                            f"API endpoint {path} returned data without authentication. "
                            "Unauthenticated APIs can expose sensitive data to anonymous users."
                        ),
                        evidence=f"GET {path} → HTTP 200 with JSON data",
                        fix=(
                            "Implement authentication on all API endpoints (JWT/OAuth2). "
                            "Add authorisation checks for each resource. "
                            "Document and version your API. Implement rate limiting."
                        ),
                        cvss_score=8.6,
                    )

                # Swagger/OpenAPI exposure
                if path in ("/swagger", "/api-docs", "/openapi.json"):
                    self.add_finding(
                        title=f"API Documentation Publicly Accessible: {path}",
                        severity="LOW",
                        category="API Security",
                        description=(
                            f"API documentation at {path} is publicly accessible. "
                            "This reveals all endpoints, parameters, and data models to attackers."
                        ),
                        evidence=f"GET {self.url + path} → HTTP 200",
                        fix="Restrict API docs to authenticated users or internal networks only.",
                    )

        # Check for rate limiting
        responses = []
        for _ in range(5):
            resp = await self.fetch(self.url + "/api/v1/users")
            if resp:
                responses.append(resp.status)
        if responses and all(s == 200 for s in responses):
            if "X-RateLimit-Limit" not in (responses[0] if responses else {}):
                self.add_finding(
                    title="API Rate Limiting Not Detected",
                    severity="MEDIUM",
                    category="API Security",
                    description=(
                        "No rate limiting headers (X-RateLimit-*) detected on API endpoints. "
                        "Without rate limiting, attackers can perform brute-force, enumeration, and DoS attacks."
                    ),
                    evidence="X-RateLimit-Limit header absent from API responses",
                    fix="Implement rate limiting (e.g., via API gateway, Nginx limit_req, or middleware). Return 429 when exceeded.",
                )

        return self.result()


# ─────────────────────────────────────────────────────────────────────────────
# Dependency / Technology CVE Scanner
# ─────────────────────────────────────────────────────────────────────────────
KNOWN_VULNERABLE = {
    "jquery": {"1.": "CVE-2019-11358", "2.1": "CVE-2019-11358", "3.4": "CVE-2019-11358"},
    "angular": {"1.": "CVE-2022-25844"},
    "bootstrap": {"3.": "CVE-2018-14041"},
    "lodash": {"4.17.20": "CVE-2021-23337"},
    "wordpress": {"5.": "CVE-2022-21661"},
}


class DependencyScanner(BaseScanner):
    async def run(self):
        resp = await self.fetch(self.url)
        if not resp:
            return self.result()

        body = resp.text()
        technologies = []

        # Detect JS libraries from script tags
        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE)
        for src in scripts:
            for lib, vuln_versions in KNOWN_VULNERABLE.items():
                if lib in src.lower():
                    version_match = re.search(r'(\d+\.\d+\.?\d*)', src)
                    version = version_match.group(1) if version_match else "unknown"
                    cve = None
                    for vuln_ver, cve_id in vuln_versions.items():
                        if version.startswith(vuln_ver):
                            cve = cve_id
                            break
                    technologies.append({"name": lib, "version": version, "vulnerable": bool(cve), "cve": cve})
                    if cve:
                        self.add_finding(
                            title=f"Vulnerable Library: {lib} {version} ({cve})",
                            severity="HIGH",
                            category="Dependency Vulnerabilities",
                            description=(
                                f"{lib} version {version} has a known vulnerability ({cve}). "
                                "Outdated libraries are a common attack vector."
                            ),
                            evidence=f"Script src: {src}",
                            fix=f"Update {lib} to the latest stable version. Subscribe to security advisories.",
                            cve_ids=[cve],
                            cvss_score=7.5,
                        )

        return {"findings": self.findings, "technologies": technologies}


# ─────────────────────────────────────────────────────────────────────────────
# Subdomain Takeover Scanner
# ─────────────────────────────────────────────────────────────────────────────
TAKEOVER_SIGNATURES = {
    "GitHub": "There isn't a GitHub Pages site here",
    "Heroku": "No such app",
    "Shopify": "Sorry, this shop is currently unavailable",
    "AWS S3": "NoSuchBucket",
    "Fastly": "Fastly error: unknown domain",
    "Netlify": "Not Found - Request ID",
}


class SubdomainScanner(BaseScanner):
    COMMON_SUBDOMAINS = ["www", "mail", "dev", "staging", "api", "static", "cdn", "blog", "shop"]

    async def run(self):
        from urllib.parse import urlparse
        hostname = urlparse(self.url).hostname or ""
        parts = hostname.split(".")
        if len(parts) < 2:
            return self.result()
        domain = ".".join(parts[-2:])

        for sub in self.COMMON_SUBDOMAINS[:5]:
            sub_url = f"https://{sub}.{domain}"
            resp = await self.fetch(sub_url)
            if resp and resp.status == 200:
                body = resp.text()
                for provider, sig in TAKEOVER_SIGNATURES.items():
                    if sig in body:
                        self.add_finding(
                            title=f"Subdomain Takeover Risk: {sub}.{domain} ({provider})",
                            severity="CRITICAL",
                            category="Subdomain Takeover",
                            description=(
                                f"The subdomain {sub}.{domain} is pointing to {provider} but "
                                "the service account is unclaimed. Attackers can claim this service "
                                "and serve malicious content under your domain."
                            ),
                            evidence=f"{sub_url} → {provider} signature: '{sig}'",
                            fix=(
                                f"Either claim the {provider} resource immediately or "
                                "remove the DNS record pointing to the unclaimed service."
                            ),
                            cvss_score=9.8,
                        )

        return self.result()


# ─────────────────────────────────────────────────────────────────────────────
# DNS Misconfiguration Scanner
# ─────────────────────────────────────────────────────────────────────────────
class DNSScanner(BaseScanner):
    async def run(self):
        from urllib.parse import urlparse
        import asyncio
        hostname = urlparse(self.url).hostname or ""

        try:
            loop = asyncio.get_event_loop()

            # SPF record check
            try:
                txt_records = await loop.run_in_executor(None, lambda: socket.getaddrinfo(hostname, None))
                if not txt_records:
                    self.add_finding(
                        title="DNS Resolution Failed",
                        severity="HIGH",
                        category="DNS",
                        description=f"Could not resolve DNS for {hostname}. Site may be down or DNS misconfigured.",
                        evidence=f"getaddrinfo({hostname}) returned empty",
                        fix="Check DNS A/AAAA records are correctly configured.",
                    )
            except socket.gaierror:
                self.add_finding(
                    title="DNS Resolution Failed",
                    severity="HIGH",
                    category="DNS",
                    description=f"DNS lookup failed for {hostname}.",
                    evidence="socket.gaierror during DNS resolution",
                    fix="Check your DNS configuration and nameserver settings.",
                )

        except Exception as e:
            logger.debug(f"DNS scan error: {e}")

        return self.result()
