"""
WebGuard AI — FastAPI Backend
Entry point for the security scanning API.
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, HttpUrl
from typing import Optional
import uuid
import logging

from routers import scan_router, report_router, health_router
from core.config import settings
from core.database import connect_db, disconnect_db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="WebGuard AI",
    description="Deep website security, performance & SEO analysis API",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "https://webguard-omega.vercel.app",
        "https://webguard-aii-1.onrender.com",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router.router, prefix="/api/v1", tags=["health"])
app.include_router(scan_router.router,   prefix="/api/v1", tags=["scan"])
app.include_router(report_router.router, prefix="/api/v1", tags=["reports"])

@app.on_event("startup")
async def startup():
    logger.info("WebGuard AI starting up...")
    await connect_db()

@app.on_event("shutdown")
async def shutdown():
    logger.info("WebGuard AI shutting down...")
    await disconnect_db()

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "status_code": exc.status_code},
    )
