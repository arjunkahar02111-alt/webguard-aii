"""
WebGuard AI — Performance Scanner
Measures page load metrics, asset optimisation, and caching.
"""
from scanners.base import BaseScanner
import time
import re
import logging

logger = logging.getLogger(__name__)


class PerformanceScanner(BaseScanner):
    async def run(self) -> dict:
        start = time.time()
        resp = await self.fetch(self.url)
        load_time = (time.time() - start) * 1000  # ms

        if not resp:
            return {"findings": self.findings, "load_time_ms": 0, "score": 0}

        headers = resp.headers
        body = resp.text()
        body_bytes = body.encode("utf-8")

        ttfb_ms = int(load_time * 0.4)  # Estimate TTFB as ~40% of total
        page_size_kb = len(body_bytes) // 1024
        requests = len(re.findall(r'<(?:script|link|img)[^>]+(?:src|href)=["\']', body, re.IGNORECASE))

        # Compression
        encoding = headers.get("Content-Encoding", "")
        compression = "enabled" if encoding in ("gzip", "br", "deflate", "zstd") else "disabled"
        if compression == "disabled" and page_size_kb > 50:
            self.add_finding(
                title="HTTP Compression Disabled",
                severity="LOW",
                category="Performance",
                description=(
                    f"Response is {page_size_kb}KB and compression is disabled. "
                    "Enabling gzip/brotli can reduce transfer size by 60-80%."
                ),
                evidence=f"Content-Encoding: {encoding or 'absent'}, Page size: {page_size_kb}KB",
                fix="Enable gzip/brotli in your web server: Nginx: gzip on; gzip_types text/html text/css application/javascript;",
            )

        # Caching
        cache_ctrl = headers.get("Cache-Control", "")
        expires = headers.get("Expires", "")
        if not cache_ctrl and not expires:
            caching = "none"
            self.add_finding(
                title="No Cache-Control Headers Set",
                severity="LOW",
                category="Performance",
                description="No caching headers are set. Browsers will re-fetch all assets on each visit, increasing load times.",
                evidence="Cache-Control and Expires headers absent",
                fix="Add Cache-Control: public, max-age=31536000 for static assets. Use Cache-Control: no-cache for dynamic content.",
            )
        elif "no-cache" in cache_ctrl or "no-store" in cache_ctrl:
            caching = "poor"
        else:
            caching = "good"

        # CDN detection
        cdn_headers = ["X-Cache", "CF-Ray", "X-Served-By", "X-Fastly", "Via", "X-Cache-Status"]
        cdn_detected = any(h in headers for h in cdn_headers)
        cdn = "detected" if cdn_detected else "not detected"

        if not cdn_detected:
            self.add_finding(
                title="No CDN Detected",
                severity="INFO",
                category="Performance",
                description="No Content Delivery Network was detected. A CDN can significantly improve load times globally.",
                evidence="None of the common CDN headers found",
                fix="Consider using Cloudflare, AWS CloudFront, or Fastly to serve assets from edge locations.",
            )

        # Load time check
        if load_time > 3000:
            self.add_finding(
                title=f"Slow Page Load Time: {int(load_time)}ms",
                severity="MEDIUM",
                category="Performance",
                description=f"Page took {int(load_time)}ms to load. Google recommends under 3 seconds for good user experience.",
                evidence=f"Measured load time: {int(load_time)}ms",
                fix="Optimise assets: minify CSS/JS, compress images, reduce render-blocking resources, enable caching.",
            )

        # Score calculation
        score = 100
        if load_time > 5000: score -= 30
        elif load_time > 3000: score -= 15
        if compression == "disabled": score -= 15
        if caching == "none": score -= 15
        if not cdn_detected: score -= 10
        if requests > 50: score -= 10
        score = max(0, score)

        return {
            "findings": self.findings,
            "load_time_ms": int(load_time),
            "ttfb_ms": ttfb_ms,
            "page_size_kb": page_size_kb,
            "requests": requests,
            "compression": compression,
            "caching": caching,
            "cdn": cdn,
            "score": score,
        }
