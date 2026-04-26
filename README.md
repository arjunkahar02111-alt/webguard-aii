# WebGuard AI 🛡️

**Deep website security, performance & SEO analysis — powered by AI.**

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                         WebGuard AI                              │
│                                                                  │
│  ┌─────────────┐    ┌──────────────┐    ┌────────────────────┐  │
│  │  React UI   │───▶│  FastAPI     │───▶│  Celery Workers    │  │
│  │  (Vite +    │    │  Backend     │    │  (Scanner Modules) │  │
│  │  Tailwind)  │    │  Port 8000   │    │                    │  │
│  └─────────────┘    └──────┬───────┘    └─────────┬──────────┘  │
│                            │                      │              │
│                    ┌───────▼──────────────────────▼──────────┐  │
│                    │  Redis (broker + result backend)        │  │
│                    └──────────────┬─────────────────────────┘   │
│                                   │                              │
│                    ┌──────────────▼─────────────────────────┐   │
│                    │  MongoDB (scan results + history)      │   │
│                    └────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

## Security Modules (20+ checks)

| Module | Detects |
|--------|---------|
| `injection.py` | SQL, Command, NoSQL injection |
| `xss.py` | Reflected, DOM-based XSS |
| `csrf.py` | Missing CSRF tokens, SameSite |
| `headers.py` | HSTS, CSP, X-Frame-Options, etc. |
| `ssl_tls.py` | Weak protocols, expiry, ciphers |
| `cors.py` | Wildcard, origin reflection |
| `cookies.py` | HttpOnly, Secure, SameSite flags |
| `auth.py` | Brute-force, 2FA, default creds |
| `idor.py` | Insecure direct object references |
| `open_redirect.py` | Open redirect parameters |
| `ssrf.py` | Server-side request forgery |
| `traversal.py` | Directory/path traversal |
| `clickjacking.py` | X-Frame-Options / CSP frame-ancestors |
| `file_upload.py` | Upload endpoint validation |
| `api_security.py` | Unauth access, rate limiting |
| `dependencies.py` | CVE-matched library versions |
| `subdomain.py` | Subdomain takeover detection |
| `dns_check.py` | DNS misconfiguration |
| `business_logic.py` | Role bypass, price manipulation |
| `rce_cache.py` | SSTI, cache poisoning, RCE patterns |
| `sensitive_data.py` | Exposed keys, .env, config files |
| `session.py` | Session fixation, expiry |

---

## Quick Start

### Option 1 — Docker Compose (Recommended)

```bash
# 1. Clone the repo
git clone https://github.com/yourorg/webguard-ai.git
cd webguard-ai

# 2. Configure environment
cp backend/.env.example backend/.env
# Edit backend/.env — set SECRET_KEY, CORS_ORIGINS, etc.

# 3. Launch the full stack
docker compose up --build

# Services:
# Frontend  → http://localhost:3000
# API docs  → http://localhost:8000/api/docs
# Flower    → http://localhost:5555  (Celery monitoring)
```

### Option 2 — Local Development

#### Prerequisites
- Python 3.11+
- Node.js 20+
- MongoDB 7.0
- Redis 7.x

#### Backend

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env as needed

# Start FastAPI
uvicorn main:app --reload --port 8000

# In a separate terminal — start Celery worker
celery -A core.celery_app worker -l info -Q scans,quick --concurrency=4

# Optional — Celery Flower monitoring
celery -A core.celery_app flower --port=5555
```

#### Frontend

```bash
cd frontend

# Install dependencies
npm install

# Set API URL (or use the Vite proxy — no config needed for localhost)
# VITE_API_URL=http://localhost:8000/api/v1  (optional .env.local)

# Start dev server
npm run dev
# Opens at http://localhost:3000

# Build for production
npm run build
```

---

## API Reference

### Start a Scan

```bash
POST /api/v1/scan
Content-Type: application/json

{
  "url": "https://example.com",
  "scan_type": "full"        # full | quick | security_only | performance_only
}

# Response:
{
  "scan_id": "uuid",
  "status": "queued",
  "poll_url": "/api/v1/scan/{scan_id}"
}
```

### Poll Scan Status

```bash
GET /api/v1/scan/{scan_id}

# Returns full ScanResult once status == "complete"
```

### Get Reports

```bash
GET /api/v1/report/{scan_id}        # JSON
GET /api/v1/report/{scan_id}/html   # Rendered HTML
GET /api/v1/report/{scan_id}/pdf    # PDF download

# List recent scans
GET /api/v1/scans?limit=20&skip=0

# Delete a scan
DELETE /api/v1/scan/{scan_id}
```

### Health Checks

```bash
GET /api/v1/health        # Liveness probe
GET /api/v1/health/ready  # Readiness probe (MongoDB + Redis)
```

---

## Project Structure

```
webguard-ai/
├── backend/
│   ├── main.py                          # FastAPI entry point
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── .env.example
│   ├── core/
│   │   ├── config.py                    # Pydantic settings
│   │   ├── database.py                  # MongoDB (Motor)
│   │   ├── celery_app.py                # Celery + Redis
│   │   └── rate_limit.py                # slowapi rate limiter
│   ├── models/
│   │   └── scan_models.py               # Pydantic models
│   ├── routers/
│   │   ├── scan_router.py               # /scan endpoints
│   │   ├── report_router.py             # /report endpoints
│   │   └── health_router.py             # /health endpoints
│   ├── tasks/
│   │   └── scan_tasks.py                # Celery task orchestrator
│   └── scanners/
│       ├── base.py                      # BaseScanner class
│       ├── security/
│       │   ├── injection.py             # SQL/NoSQL/Command injection
│       │   ├── xss.py                   # XSS + all security scanners
│       │   ├── business_logic.py        # Business logic flaws
│       │   ├── rce_cache.py             # RCE + cache poisoning
│       │   └── sensitive_data.py        # Data exposure + sessions
│       ├── performance/
│       │   └── perf_audit.py            # Load time, compression, CDN
│       ├── seo/
│       │   └── seo_audit.py             # Meta, H1, sitemap, schema
│       └── utils/
│           └── risk_scorer.py           # CVSS-based scoring
│
├── frontend/
│   ├── index.html
│   ├── vite.config.js
│   ├── tailwind.config.js
│   ├── package.json
│   ├── Dockerfile
│   ├── nginx.conf
│   └── src/
│       ├── main.jsx
│       ├── App.jsx
│       ├── index.css
│       └── components/
│           ├── Header.jsx
│           ├── ScanForm.jsx
│           ├── ScanProgress.jsx
│           ├── ResultsDashboard.jsx
│           ├── FindingCard.jsx
│           ├── ScoreRing.jsx
│           └── MetricsGrid.jsx
│
└── docker-compose.yml
```

---

## Ethical Usage & Legal Notice

WebGuard AI uses **safe, non-destructive scanning techniques only**:

- All payloads are observation-based — no data is modified or deleted
- Probes use benign values that produce observable differences without harm
- Safe mode is always enabled and cannot be disabled via API
- Rate limiting prevents accidental DoS

> ⚠️ **Only scan websites you own or have explicit written permission to test.**
> Unauthorized scanning may violate computer fraud laws in your jurisdiction.

---

## Extending WebGuard AI

### Adding a New Scanner Module

```python
# backend/scanners/security/my_scanner.py
from scanners.base import BaseScanner

class MyScanner(BaseScanner):
    async def run(self):
        resp = await self.fetch(self.url)
        if resp and "vulnerable_pattern" in resp.text():
            self.add_finding(
                title="My Vulnerability",
                severity="HIGH",          # CRITICAL|HIGH|MEDIUM|LOW|INFO
                category="My Category",
                description="What the issue is and why it matters.",
                evidence="What triggered this finding.",
                fix="How to fix it, step by step.",
                cvss_score=7.5,
            )
        return self.result()
```

Then import and add to `SECURITY_SCANNERS` in `tasks/scan_tasks.py`.

---

## License

MIT — see LICENSE file.
