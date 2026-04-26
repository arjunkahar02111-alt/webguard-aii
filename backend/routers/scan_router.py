"""
WebGuard AI — Scan Router
POST /scan        → queue a new scan
GET  /scan/{id}  → poll scan status/results
GET  /scans      → list recent scans
"""
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from models.scan_models import ScanRequest, ScanResult, ScanInitResponse, ScanStatus
from core.database import get_db
from tasks.scan_tasks import _execute_full_scan, _execute_quick_scan
import uuid
from datetime import datetime

router = APIRouter()


@router.post("/scan", response_model=ScanInitResponse)
async def initiate_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    db = get_db()

    scan_doc = {
        "scan_id": scan_id,
        "url": str(request.url),
        "hostname": str(request.url).split("/")[2] if "/" in str(request.url) else str(request.url),
        "status": ScanStatus.QUEUED,
        "scan_type": request.scan_type,
        "created_at": datetime.utcnow(),
        "findings": [],
    }
    await db.scans.insert_one(scan_doc)

    # Dispatch Background task
    if request.scan_type == "quick":
        background_tasks.add_task(_execute_quick_scan, None, scan_id, str(request.url))
    else:
        background_tasks.add_task(_execute_full_scan, None, scan_id, str(request.url), request.scan_type)

    return ScanInitResponse(
        scan_id=scan_id,
        status=ScanStatus.QUEUED,
        message="Scan queued successfully",
        poll_url=f"/api/v1/scan/{scan_id}",
    )


@router.get("/scan/{scan_id}", response_model=ScanResult)
async def get_scan_result(scan_id: str):
    db = get_db()
    doc = await db.scans.find_one({"scan_id": scan_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanResult(**doc)


@router.get("/scans")
async def list_scans(limit: int = 20, skip: int = 0):
    db = get_db()
    cursor = db.scans.find({}, {"_id": 0, "findings": 0}).sort("created_at", -1).skip(skip).limit(limit)
    scans = await cursor.to_list(length=limit)
    return {"scans": scans, "total": await db.scans.count_documents({})}


@router.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str):
    db = get_db()
    result = await db.scans.delete_one({"scan_id": scan_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"message": "Scan deleted", "scan_id": scan_id}
