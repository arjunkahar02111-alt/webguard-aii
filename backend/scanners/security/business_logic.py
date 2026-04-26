"""
WebGuard AI — Business Logic & Broken Access Control Scanner
Detects role-bypass patterns, abnormal parameter flows, and price manipulation risks.
"""
from scanners.base import BaseScanner
import re
import logging

logger = logging.getLogger(__name__)


class BusinessLogicScanner(BaseScanner):
    """
    Simulates business logic abuse patterns:
    - Price/quantity parameter tampering
    - Role/privilege parameter in URLs
    - Negative value inputs
    - Step-skipping in multi-step flows
    """

    PRIVILEGE_PARAMS = ["role", "admin", "is_admin", "privilege", "level", "access", "group", "permission"]
    PRICE_PARAMS     = ["price", "amount", "total", "cost", "fee", "discount"]
    STEP_PARAMS      = ["step", "stage", "phase", "page", "flow"]

    async def run(self):
        resp = await self.fetch(self.url)
        if not resp:
            return self.result()

        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(self.url)
        qs = parse_qs(parsed.query)
        body = resp.text()

        await self._check_role_params(qs, parsed)
        await self._check_price_manipulation(qs, parsed)
        await self._check_step_skipping(qs, parsed)
        self._check_hidden_admin_inputs(body)

        return self.result()

    async def _check_role_params(self, qs, parsed):
        from urllib.parse import urlencode, urlunparse
        found = [k for k in qs if k.lower() in self.PRIVILEGE_PARAMS]
        for param in found:
            # Try escalating to admin
            test_vals = ["admin", "1", "true", "superuser", "root"]
            for val in test_vals:
                test_qs = dict(qs)
                test_qs[param] = [val]
                test_url = urlunparse(parsed._replace(query=urlencode(test_qs, doseq=True)))
                r = await self.fetch(test_url)
                if r and r.status == 200:
                    body = r.text().lower()
                    if any(kw in body for kw in ["admin panel", "dashboard", "manage users", "settings"]):
                        self.add_finding(
                            title=f"Role/Privilege Escalation via URL Parameter '{param}'",
                            severity="CRITICAL",
                            category="Broken Access Control",
                            description=(
                                f"Setting '{param}={val}' in the URL returned an admin-like response. "
                                "Privilege escalation via client-controlled parameters allows any user "
                                "to gain administrative access."
                            ),
                            evidence=f"?{param}={val} → HTTP 200 with admin content",
                            fix=(
                                "Never use client-supplied parameters to determine roles or permissions. "
                                "Read role from the authenticated session/token server-side only. "
                                "Implement attribute-based access control (ABAC)."
                            ),
                            cvss_score=9.9,
                        )
                        return

            self.add_finding(
                title=f"Privilege Parameter Exposed in URL: '{param}'",
                severity="MEDIUM",
                category="Broken Access Control",
                description=(
                    f"A privilege-related parameter '{param}' is present in the URL. "
                    "Even if server-side validation exists, exposing this creates an "
                    "attack surface for parameter tampering and confused deputy problems."
                ),
                evidence=f"Parameter '{param}' found in query string",
                fix=(
                    "Remove privilege parameters from URLs entirely. "
                    "Derive all authorisation decisions from the server-side session."
                ),
                cvss_score=6.5,
            )

    async def _check_price_manipulation(self, qs, parsed):
        from urllib.parse import urlencode, urlunparse
        found = [k for k in qs if k.lower() in self.PRICE_PARAMS]
        for param in found:
            # Try negative and zero values
            for val in ["-1", "0", "0.001"]:
                test_qs = dict(qs)
                test_qs[param] = [val]
                test_url = urlunparse(parsed._replace(query=urlencode(test_qs, doseq=True)))
                r = await self.fetch(test_url)
                if r and r.status == 200:
                    self.add_finding(
                        title=f"Price/Amount Parameter Manipulation Risk: '{param}'",
                        severity="HIGH",
                        category="Business Logic",
                        description=(
                            f"Parameter '{param}' controls a price/amount value and accepted '{val}'. "
                            "If server-side validation is absent, attackers can purchase items for "
                            "negative amounts, zero cost, or manipulate totals."
                        ),
                        evidence=f"?{param}={val} → HTTP 200",
                        fix=(
                            "Always validate prices and amounts server-side against a trusted source "
                            "(e.g., product catalog). Never trust client-submitted prices. "
                            "Enforce positive minimum values and maximum sanity checks."
                        ),
                        cvss_score=8.6,
                    )
                    break

    async def _check_step_skipping(self, qs, parsed):
        from urllib.parse import urlencode, urlunparse
        found = [k for k in qs if k.lower() in self.STEP_PARAMS]
        for param in found:
            current = qs.get(param, ["1"])[0]
            if current.isdigit():
                # Try jumping to final step
                for jump in ["99", "100", "final", "complete", "confirm"]:
                    test_qs = dict(qs)
                    test_qs[param] = [jump]
                    test_url = urlunparse(parsed._replace(query=urlencode(test_qs, doseq=True)))
                    r = await self.fetch(test_url)
                    if r and r.status == 200:
                        body = r.text().lower()
                        if any(kw in body for kw in ["confirm", "complete", "success", "thank you", "order"]):
                            self.add_finding(
                                title=f"Multi-Step Flow Step-Skip via '{param}'",
                                severity="HIGH",
                                category="Business Logic",
                                description=(
                                    f"Jumping {param} to '{jump}' reached a completion page, "
                                    "bypassing intermediate validation steps. Attackers can skip "
                                    "payment, verification, or agreement steps."
                                ),
                                evidence=f"?{param}={jump} → completion page detected",
                                fix=(
                                    "Track flow state server-side in the session, not via URL parameters. "
                                    "Validate that previous steps were completed before allowing progression."
                                ),
                                cvss_score=7.5,
                            )
                            break

    def _check_hidden_admin_inputs(self, body: str):
        hidden = re.findall(r'<input[^>]+type=["\']hidden["\'][^>]+>', body, re.IGNORECASE)
        for inp in hidden:
            name = re.search(r'name=["\']([^"\']+)["\']', inp)
            if name and any(p in name.group(1).lower() for p in self.PRIVILEGE_PARAMS + ["user_id", "account_id"]):
                self.add_finding(
                    title=f"Sensitive Hidden Field Exposed: '{name.group(1)}'",
                    severity="MEDIUM",
                    category="Business Logic",
                    description=(
                        f"Hidden form field '{name.group(1)}' may be client-tamperable. "
                        "Attackers can modify hidden fields to escalate privileges or impersonate users."
                    ),
                    evidence=f"Hidden input: {inp[:200]}",
                    fix=(
                        "Never use hidden fields for security-sensitive values. "
                        "Use server-side sessions. If needed, HMAC-sign the value and verify server-side."
                    ),
                    cvss_score=6.3,
                )
