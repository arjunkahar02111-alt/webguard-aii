"""
WebGuard AI — Report Router
GET /report/{scan_id}       → JSON full report
GET /report/{scan_id}/html  → Rendered HTML report
GET /report/{scan_id}/pdf   → PDF (WeasyPrint)
"""
from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, Response
from core.database import get_db
from datetime import datetime
import json

router = APIRouter()

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>WebGuard AI — Security Report: {hostname}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f5f7fa; color: #1a202c; }}
  .cover {{ background: #0a0c10; color: #fff; padding: 60px 48px; }}
  .cover h1 {{ font-size: 32px; font-weight: 300; margin-bottom: 8px; }}
  .cover h1 span {{ color: #00d4aa; }}
  .cover .url {{ font-family: monospace; font-size: 14px; color: #6b7280; margin-top: 12px; }}
  .cover .meta {{ display: flex; gap: 32px; margin-top: 24px; }}
  .cover .meta div {{ font-size: 12px; color: #9ca3af; }}
  .cover .meta strong {{ display: block; font-size: 22px; color: #fff; }}
  .score-badge {{ display: inline-block; padding: 6px 18px; border-radius: 6px; font-weight: 700; font-size: 14px; margin-top: 16px; }}
  .CRITICAL {{ background: #ff2d5520; color: #ff2d55; border: 1px solid #ff2d5540; }}
  .HIGH {{ background: #ff444420; color: #ff4444; border: 1px solid #ff444440; }}
  .MEDIUM {{ background: #ffaa0020; color: #ffaa00; border: 1px solid #ffaa0040; }}
  .LOW {{ background: #00d4aa20; color: #00d4aa; border: 1px solid #00d4aa40; }}
  .container {{ max-width: 900px; margin: 0 auto; padding: 40px 24px; }}
  .section {{ background: #fff; border-radius: 12px; border: 1px solid #e5e7eb; padding: 24px; margin-bottom: 20px; }}
  .section h2 {{ font-size: 16px; font-weight: 600; margin-bottom: 16px; padding-bottom: 10px; border-bottom: 1px solid #f3f4f6; }}
  .finding {{ border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px; margin-bottom: 10px; }}
  .finding .sev {{ display: inline-block; font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 4px; margin-bottom: 8px; letter-spacing: 1px; }}
  .finding h3 {{ font-size: 14px; font-weight: 600; margin-bottom: 6px; }}
  .finding .desc {{ font-size: 13px; color: #4b5563; line-height: 1.6; }}
  .finding .fix {{ background: #f0fdf4; border-left: 3px solid #00d4aa; padding: 10px 12px; margin-top: 10px; font-size: 12px; border-radius: 0 6px 6px 0; }}
  .finding .evidence {{ background: #f9fafb; border: 1px solid #e5e7eb; padding: 8px 12px; margin-top: 8px; font-family: monospace; font-size: 11px; color: #6b7280; border-radius: 6px; }}
  .metrics {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }}
  .metric {{ background: #f9fafb; border-radius: 8px; padding: 14px; }}
  .metric .label {{ font-size: 11px; color: #9ca3af; text-transform: uppercase; letter-spacing: 1px; }}
  .metric .value {{ font-size: 20px; font-weight: 700; margin-top: 4px; font-family: monospace; }}
  .good {{ color: #00d4aa; }} .warn {{ color: #f59e0b; }} .bad {{ color: #ef4444; }}
  .footer {{ text-align: center; font-size: 12px; color: #9ca3af; padding: 24px; }}
</style>
</head>
<body>
<div class="cover">
  <h1>WebGuard <span>AI</span> — Security Report</h1>
  <div class="url">{url}</div>
  <div class="meta">
    <div><strong>{score}</strong>Security Score</div>
    <div><strong class="{risk_lower}">{risk}</strong>Risk Level</div>
    <div><strong>{critical}</strong>Critical</div>
    <div><strong>{high}</strong>High</div>
    <div><strong>{medium}</strong>Medium</div>
    <div><strong>{total}</strong>Total Issues</div>
  </div>
  <div class="score-badge {risk}">{risk} RISK — Score: {score}/100</div>
  <div style="margin-top:16px;font-size:13px;color:#9ca3af;">Generated: {date} by WebGuard AI</div>
</div>

<div class="container">
  <div class="section">
    <h2>Executive Summary</h2>
    <p style="font-size:14px;line-height:1.7;color:#374151;">{summary}</p>
  </div>

  <div class="section">
    <h2>Security Findings ({total_findings})</h2>
    {findings_html}
  </div>

  {perf_html}
  {seo_html}
</div>

<div class="footer">WebGuard AI — Confidential Security Report — {date}</div>
</body>
</html>"""


def _severity_color(sev: str) -> str:
    return {"CRITICAL": "#ff2d55", "HIGH": "#ff4444", "MEDIUM": "#f59e0b", "LOW": "#00d4aa", "INFO": "#6b7280"}.get(sev, "#6b7280")


def _render_html(doc: dict) -> str:
    stats = doc.get("stats") or {}
    findings = doc.get("findings") or []
    perf = doc.get("performance") or {}
    seo = doc.get("seo") or {}

    findings_html = ""
    for f in findings:
        sev = f.get("severity", "INFO")
        color = _severity_color(sev)
        findings_html += f"""
        <div class="finding">
          <span class="sev {sev}" style="background:{color}20;color:{color};border:1px solid {color}40;">{sev}</span>
          <h3>{f.get('title', '')}</h3>
          <div class="desc">{f.get('description', '')}</div>
          {'<div class="evidence">&gt; ' + f.get('evidence','') + '</div>' if f.get('evidence') else ''}
          <div class="fix"><strong style="color:#00d4aa;">FIX:</strong> {f.get('fix', '')}</div>
        </div>"""

    perf_html = ""
    if perf:
        perf_html = f"""
        <div class="section">
          <h2>Performance</h2>
          <div class="metrics">
            <div class="metric"><div class="label">Load Time</div><div class="value">{perf.get('load_time_ms',0)}ms</div></div>
            <div class="metric"><div class="label">Page Size</div><div class="value">{perf.get('page_size_kb',0)}KB</div></div>
            <div class="metric"><div class="label">Perf Score</div><div class="value">{perf.get('score',0)}/100</div></div>
          </div>
        </div>"""

    seo_html = ""
    if seo:
        seo_html = f"""
        <div class="section">
          <h2>SEO</h2>
          <div class="metrics">
            <div class="metric"><div class="label">Title Tag</div><div class="value" style="font-size:14px;">{seo.get('title_tag','')}</div></div>
            <div class="metric"><div class="label">H1 Tags</div><div class="value">{seo.get('h1_tags',0)}</div></div>
            <div class="metric"><div class="label">SEO Score</div><div class="value">{seo.get('score',0)}/100</div></div>
          </div>
        </div>"""

    risk = doc.get("risk_level", "UNKNOWN")
    return HTML_TEMPLATE.format(
        hostname=doc.get("hostname", ""),
        url=doc.get("url", ""),
        score=doc.get("overall_score", 0),
        risk=risk,
        risk_lower=risk.lower(),
        critical=stats.get("critical", 0),
        high=stats.get("high", 0),
        medium=stats.get("medium", 0),
        total=sum(stats.get(k, 0) for k in ("critical", "high", "medium", "low")),
        total_findings=len(findings),
        summary=doc.get("summary", ""),
        findings_html=findings_html,
        perf_html=perf_html,
        seo_html=seo_html,
        date=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
    )


@router.get("/report/{scan_id}")
async def get_report_json(scan_id: str):
    db = get_db()
    doc = await db.scans.find_one({"scan_id": scan_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    if doc.get("status") != "complete":
        raise HTTPException(status_code=202, detail="Scan not yet complete")
    return doc


@router.get("/report/{scan_id}/html", response_class=HTMLResponse)
async def get_report_html(scan_id: str):
    db = get_db()
    doc = await db.scans.find_one({"scan_id": scan_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    if doc.get("status") != "complete":
        raise HTTPException(status_code=202, detail="Scan not yet complete")
    return HTMLResponse(content=_render_html(doc))


@router.get("/report/{scan_id}/pdf")
async def get_report_pdf(scan_id: str):
    db = get_db()
    doc = await db.scans.find_one({"scan_id": scan_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    if doc.get("status") != "complete":
        raise HTTPException(status_code=202, detail="Scan not yet complete")
    try:
        from weasyprint import HTML
        html_content = _render_html(doc)
        pdf_bytes = HTML(string=html_content).write_pdf()
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=webguard-{scan_id[:8]}.pdf"}
        )
    except ImportError:
        raise HTTPException(status_code=501, detail="PDF export requires weasyprint: pip install weasyprint")
