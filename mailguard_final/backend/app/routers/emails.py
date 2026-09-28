from typing import List, Optional
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, Query
from sqlalchemy.orm import Session, joinedload

from ..database import get_db
from ..auth import get_current_analyst
from ..models import EmailRecord, AnalysisStep
from ..schemas import EmailListItem, EmailDetail
from ..pipeline import run_pipeline
from ..bridge import send_to_part3
router = APIRouter(prefix="/emails", tags=["emails"], dependencies=[Depends(get_current_analyst)])

MAX_UPLOAD_BYTES = 15 * 1024 * 1024  # 15 MB


@router.post("/upload", response_model=EmailDetail)
async def upload_email(file: UploadFile = File(...), db: Session = Depends(get_db)):
    if not file.filename.lower().endswith((".eml", ".msg", ".txt")):
        raise HTTPException(400, "Please upload a .eml (or .txt containing raw RFC822 email) file.")

    raw_bytes = await file.read()
    if len(raw_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(400, "File too large (max 15 MB).")
    if len(raw_bytes) == 0:
        raise HTTPException(400, "Empty file.")

    result = run_pipeline(raw_bytes, file.filename)
    send_to_part3(result, file.filename, raw_bytes)
    parsed = result["parsed"]
    fusion = result["fusion"]

    existing = db.query(EmailRecord).filter(EmailRecord.sha256 == parsed.sha256).first()
    if existing:
        raise HTTPException(409, f"This exact email was already ingested (id={existing.id}).")

    origin_step = next((s for s in result["steps"] if s["step_key"] == "origin"), None)
    geo = origin_step.get("geo") if origin_step else None

    record = EmailRecord(
        filename=file.filename,
        sha256=parsed.sha256,
        sender=parsed.from_header,
        reply_to=parsed.reply_to,
        return_path=parsed.return_path,
        subject=parsed.subject,
        date_header=parsed.date_header,
        raw_headers=parsed.raw_header_block,
        body_preview=(parsed.body_text or parsed.body_html or "")[:2000],
        fraud_score=fusion["fraud_score"],
        verdict=fusion["verdict"],
        flagged=fusion["flagged"],
        origin_ip=geo.get("ip") if geo else None,
        origin_country=geo.get("country") if geo else None,
        origin_city=geo.get("city") if geo else None,
        origin_lat=geo.get("lat") if geo else None,
        origin_lon=geo.get("lon") if geo else None,
        origin_isp=(origin_step["details"].get("isp") if origin_step else None),
        origin_is_proxy=1 if (origin_step and origin_step["details"].get("is_proxy_or_vpn")) else 0,
    )
    db.add(record)
    db.flush()

    for step in result["steps"]:
        db.add(AnalysisStep(
            email_id=record.id,
            order_index=step["order_index"],
            step_key=step["step_key"],
            title=step["title"],
            status=step["status"],
            summary=step["summary"],
            details=step["details"],
        ))

    db.commit()
    db.refresh(record)
    return _to_detail(record)


def _to_detail(record: EmailRecord) -> dict:
    return {
        "id": record.id,
        "filename": record.filename,
        "sha256": record.sha256,
        "sender": record.sender,
        "reply_to": record.reply_to,
        "return_path": record.return_path,
        "subject": record.subject,
        "date_header": record.date_header,
        "raw_headers": record.raw_headers,
        "body_preview": record.body_preview,
        "fraud_score": record.fraud_score,
        "verdict": record.verdict,
        "flagged": record.flagged,
        "origin_ip": record.origin_ip,
        "origin_country": record.origin_country,
        "origin_city": record.origin_city,
        "origin_lat": record.origin_lat,
        "origin_lon": record.origin_lon,
        "origin_isp": record.origin_isp,
        "origin_is_proxy": record.origin_is_proxy,
        "created_at": record.created_at.isoformat(),
        "steps": sorted(
            [
                {
                    "step_key": s.step_key, "title": s.title, "status": s.status,
                    "summary": s.summary, "details": s.details, "order_index": s.order_index,
                }
                for s in record.steps
            ],
            key=lambda s: s["order_index"],
        ),
    }


@router.get("", response_model=List[EmailListItem])
def list_emails(
    flagged_only: bool = Query(True, description="Only show flagged/suspicious emails (the analyst inbox)"),
    db: Session = Depends(get_db),
):
    q = db.query(EmailRecord)
    if flagged_only:
        q = q.filter(EmailRecord.flagged == 1)
    records = q.order_by(EmailRecord.created_at.desc()).all()
    return [
        {
            "id": r.id, "filename": r.filename, "sender": r.sender, "subject": r.subject,
            "fraud_score": r.fraud_score, "verdict": r.verdict, "flagged": r.flagged,
            "created_at": r.created_at.isoformat(), "origin_country": r.origin_country,
        }
        for r in records
    ]


@router.get("/{email_id}", response_model=EmailDetail)
def get_email(email_id: int, db: Session = Depends(get_db)):
    record = (
        db.query(EmailRecord)
        .options(joinedload(EmailRecord.steps))
        .filter(EmailRecord.id == email_id)
        .first()
    )
    if not record:
        raise HTTPException(404, "Email not found")
    return _to_detail(record)


@router.delete("/{email_id}")
def delete_email(email_id: int, db: Session = Depends(get_db)):
    record = db.query(EmailRecord).filter(EmailRecord.id == email_id).first()
    if not record:
        raise HTTPException(404, "Email not found")
    db.delete(record)
    db.commit()
    return {"ok": True}
