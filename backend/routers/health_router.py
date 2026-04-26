"""
WebGuard AI — Health Router
GET /health        → liveness probe
GET /health/ready  → readiness probe (checks DB + Redis)
"""
from fastapi import APIRouter
from core.database import get_db
from core.config import settings
import redis as redis_lib
from datetime import datetime

router = APIRouter()


@router.get("/health")
async def health():
    return {"status": "ok", "app": settings.APP_NAME, "timestamp": datetime.utcnow().isoformat()}


@router.get("/health/ready")
async def readiness():
    checks = {}

    # MongoDB
    try:
        db = get_db()
        await db.command("ping")
        checks["mongodb"] = "ok"
    except Exception as e:
        checks["mongodb"] = f"error: {e}"

    # Redis
    try:
        r = redis_lib.from_url(settings.REDIS_URL, socket_connect_timeout=2)
        r.ping()
        checks["redis"] = "ok"
    except Exception as e:
        checks["redis"] = f"error: {e}"

    all_ok = all(v == "ok" for v in checks.values())
    return {
        "status": "ready" if all_ok else "degraded",
        "checks": checks,
        "timestamp": datetime.utcnow().isoformat(),
    }
