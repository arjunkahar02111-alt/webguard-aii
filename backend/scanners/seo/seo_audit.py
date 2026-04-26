"""
WebGuard AI — SEO Scanner
Audits meta tags, headings, sitemap, robots.txt, and structured data.
"""
from scanners.base import BaseScanner
import re
import logging

logger = logging.getLogger(__name__)


class SEOScanner(BaseScanner):
    async def run(self) -> dict:
        resp = await self.fetch(self.url)
        if not resp:
            return {"findings": self.findings, "score": 0}

        body = resp.text()

        # ── Title Tag ─────────────────────────────────────────────────────────
        title_match = re.search(r'<title[^>]*>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
        if not title_match:
            title_tag = "missing"
            self.add_finding(
                title="Missing <title> Tag",
                severity="MEDIUM",
                category="SEO",
                description="The page has no <title> tag. Title tags are critical for SEO and browser tab display.",
                evidence="<title> not found in HTML",
                fix="Add a descriptive <title> tag: <title>Page Name | Brand Name</title>. Aim for 50-60 characters.",
            )
        else:
            title_content = title_match.group(1).strip()
            title_tag = "present"
            if len(title_content) > 60:
                self.add_finding(
                    title=f"Title Tag Too Long ({len(title_content)} chars)",
                    severity="LOW",
                    category="SEO",
                    description="Title tag exceeds 60 characters and may be truncated in search results.",
                    evidence=f"Title: '{title_content[:80]}'",
                    fix="Shorten title to under 60 characters while retaining key terms.",
                )
            elif len(title_content) < 10:
                self.add_finding(
                    title="Title Tag Too Short",
                    severity="LOW",
                    category="SEO",
                    description=f"Title tag is only {len(title_content)} characters. Short titles miss keyword opportunities.",
                    evidence=f"Title: '{title_content}'",
                    fix="Expand the title to 50-60 characters including primary keywords.",
                )

        # ── Meta Description ──────────────────────────────────────────────────
        meta_desc = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']', body, re.IGNORECASE)
        if not meta_desc:
            meta_description = "missing"
            self.add_finding(
                title="Missing Meta Description",
                severity="MEDIUM",
                category="SEO",
                description="No meta description found. Search engines use this for snippets; its absence reduces CTR.",
                evidence="<meta name='description'> not found",
                fix="Add <meta name='description' content='...'>. Aim for 150-160 characters.",
            )
        else:
            content = meta_desc.group(1)
            if len(content) < 50:
                meta_description = "too short"
            elif len(content) > 160:
                meta_description = "too long"
            else:
                meta_description = "present"

        # ── H1 Tags ──────────────────────────────────────────────────────────
        h1_tags = re.findall(r'<h1[^>]*>.*?</h1>', body, re.IGNORECASE | re.DOTALL)
        h1_count = len(h1_tags)
        if h1_count == 0:
            self.add_finding(
                title="Missing H1 Tag",
                severity="MEDIUM",
                category="SEO",
                description="No H1 tag found. H1 is the primary heading and a key on-page SEO signal.",
                evidence="<h1> not found in HTML",
                fix="Add a single H1 tag containing the page's primary keyword.",
            )
        elif h1_count > 1:
            self.add_finding(
                title=f"Multiple H1 Tags ({h1_count})",
                severity="LOW",
                category="SEO",
                description=f"{h1_count} H1 tags found. Multiple H1s dilute the primary heading signal.",
                evidence=f"{h1_count} <h1> elements in page",
                fix="Use exactly one H1 per page. Convert additional H1s to H2/H3.",
            )

        # ── Canonical ─────────────────────────────────────────────────────────
        canonical = re.search(r'<link[^>]+rel=["\']canonical["\'][^>]+>', body, re.IGNORECASE)
        canonical_status = "present" if canonical else "missing"
        if not canonical:
            self.add_finding(
                title="Missing Canonical Tag",
                severity="LOW",
                category="SEO",
                description="No canonical link tag found. Without it, search engines may index duplicate content.",
                evidence="<link rel='canonical'> not found",
                fix="Add <link rel='canonical' href='https://yoursite.com/page/'> to prevent duplicate content issues.",
            )

        # ── Sitemap ───────────────────────────────────────────────────────────
        sitemap_resp = await self.fetch(self.url + "/sitemap.xml")
        sitemap = "found" if (sitemap_resp and sitemap_resp.status == 200) else "not found"
        if sitemap == "not found":
            self.add_finding(
                title="XML Sitemap Not Found",
                severity="LOW",
                category="SEO",
                description="No sitemap.xml found. Sitemaps help search engines discover and index all pages.",
                evidence=f"GET {self.url}/sitemap.xml → {sitemap_resp.status if sitemap_resp else 'no response'}",
                fix="Generate and submit a sitemap.xml. Reference it in robots.txt: Sitemap: https://yoursite.com/sitemap.xml",
            )

        # ── Robots.txt ────────────────────────────────────────────────────────
        robots_resp = await self.fetch(self.url + "/robots.txt")
        robots_txt = "found" if (robots_resp and robots_resp.status == 200) else "not found"

        # ── Structured Data ───────────────────────────────────────────────────
        has_schema = '"@context"' in body or "application/ld+json" in body
        structured_data = "present" if has_schema else "missing"
        if not has_schema:
            self.add_finding(
                title="No Structured Data (Schema.org) Found",
                severity="LOW",
                category="SEO",
                description="No JSON-LD/Schema.org structured data found. Structured data enables rich search results.",
                evidence="No application/ld+json or @context found",
                fix="Add JSON-LD structured data. Example: Organization, Product, Article schemas via schema.org",
            )

        # ── Score ─────────────────────────────────────────────────────────────
        score = 100
        if title_tag == "missing": score -= 20
        if meta_description == "missing": score -= 15
        if h1_count == 0: score -= 15
        if canonical_status == "missing": score -= 10
        if sitemap == "not found": score -= 10
        if robots_txt == "not found": score -= 5
        if not has_schema: score -= 10
        score = max(0, score)

        return {
            "findings": self.findings,
            "title_tag": title_tag,
            "meta_description": meta_description,
            "h1_tags": h1_count,
            "canonical": canonical_status,
            "sitemap": sitemap,
            "robots_txt": robots_txt,
            "broken_links": 0,   # Requires crawling, set as async enhancement
            "structured_data": structured_data,
            "score": score,
        }
