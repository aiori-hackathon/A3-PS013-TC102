"""TraceForge API: user-scoped evidence intake, transparent analysis and reporting."""
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import csv, hashlib, io, json, logging, uuid, zipfile
from pathlib import Path

import jwt
from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import reportlab
from sqlalchemy import desc, func, select, inspect, text
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm import Session

from app.analysis_service import analyse_events, parse_log
from app.config import ALLOWED_EXTENSIONS, BASE_DIR, MAX_UPLOAD_MB, REPORT_DIR, UPLOAD_DIR
from app.database import Base, engine, get_db
from app.models import AuditLog, Evidence, Event, Finding, Investigation, Report, User
from app.schemas import LoginRequest, RegisterRequest, SettingsRequest
from app.security import create_access_token, hash_password, verify_password, decode_access_token

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("traceforge")


def migrate_existing_database():
    """Additive SQLite migration for older starter-project databases; never drops user data."""
    Base.metadata.create_all(bind=engine)
    if engine.dialect.name != "sqlite":
        return
    additions = {
        "users": {"display_timezone": "VARCHAR(64) NOT NULL DEFAULT 'UTC'"},
        "evidence": {"investigation_id": "INTEGER"},
        "findings": {"rule_id": "VARCHAR(50) NOT NULL DEFAULT 'GEN-000'", "rationale": "TEXT NOT NULL DEFAULT ''",
                     "recommended_action": "TEXT NOT NULL DEFAULT ''", "event_ids": "TEXT NOT NULL DEFAULT '[]'",
                     "start_timestamp": "VARCHAR(80)", "end_timestamp": "VARCHAR(80)"},
    }
    with engine.begin() as connection:
        inspector = inspect(connection)
        for table, columns in additions.items():
            existing = {column["name"] for column in inspector.get_columns(table)}
            for name, declaration in columns.items():
                if name not in existing:
                    connection.execute(text(f'ALTER TABLE "{table}" ADD COLUMN "{name}" {declaration}'))
    # Preserve legacy evidence by attaching ungrouped records to a per-user migration case.
    with OrmSession(engine) as db:
        users = db.scalars(select(User)).all()
        for user in users:
            case = db.scalar(select(Investigation).where(Investigation.owner_id == user.id).order_by(Investigation.id))
            unassigned = db.scalars(select(Evidence).where(Evidence.owner_id == user.id, Evidence.investigation_id.is_(None))).all()
            if case is None:
                case = Investigation(owner_id=user.id, title="Migrated investigation", description="Created during an additive upgrade to preserve existing evidence grouping.")
                db.add(case); db.flush()
            if case:
                for item in unassigned:
                    item.investigation_id = case.id
        db.commit()

@asynccontextmanager
async def lifespan(app: FastAPI):
    migrate_existing_database()
    yield

app = FastAPI(title="TraceForge", description="Digital evidence and incident investigation workspace", version="1.3.0", lifespan=lifespan)
app.mount("/static", __import__("fastapi.staticfiles", fromlist=["StaticFiles"]).StaticFiles(directory=str(BASE_DIR / "static")), name="static")
bearer = HTTPBearer(auto_error=False)

@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response

@app.get("/", include_in_schema=False)
def home():
    return FileResponse(BASE_DIR / "static" / "index.html")

def audit(db: Session, user_id: int, action: str, target: str = "", outcome: str = "success"):
    db.add(AuditLog(owner_id=user_id, action=action[:100], target=target[:255], outcome=outcome[:30]))

def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer), db: Session = Depends(get_db)) -> User:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Sign in to continue")
    try:
        user_id = decode_access_token(credentials.credentials)
    except (jwt.PyJWTError, ValueError, KeyError, TypeError):
        raise HTTPException(status_code=401, detail="Session expired or invalid. Please sign in again.")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=401, detail="Account not found")
    return user

def iso(value):
    if value is None: return None
    if value.tzinfo is None: return value.isoformat() + "Z"
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

def investigation_dict(item: Investigation, evidence_count: int | None = None):
    return {"id": item.id, "title": item.title, "description": item.description, "status": item.status,
            "created_at": iso(item.created_at), "updated_at": iso(item.updated_at), "evidence_count": evidence_count}

def evidence_dict(item: Evidence):
    return {"id": item.id, "filename": item.original_name, "size_bytes": item.size_bytes,
            "sha256": item.sha256, "status": item.status, "event_count": item.event_count,
            "finding_count": item.finding_count, "parsing_gaps": item.parsing_gaps,
            "created_at": iso(item.created_at), "error_message": item.error_message,
            "investigation_id": item.investigation_id,
            "investigation_title": item.investigation.title if item.investigation else None}

def finding_dict(f: Finding):
    try: linked = json.loads(f.event_ids or "[]")
    except (TypeError, json.JSONDecodeError): linked = []
    return {"id": f.id, "severity": f.severity, "title": f.title, "description": f.description,
            "event_count": f.event_count, "rule_id": f.rule_id, "rationale": f.rationale,
            "recommended_action": f.recommended_action, "event_ids": linked,
            "start_timestamp": f.start_timestamp, "end_timestamp": f.end_timestamp}

def owned_evidence(evidence_id: int, user: User, db: Session) -> Evidence:
    item = db.scalar(select(Evidence).where(Evidence.id == evidence_id, Evidence.owner_id == user.id))
    if not item: raise HTTPException(status_code=404, detail="Evidence not found")
    return item

def owned_investigation(investigation_id: int, user: User, db: Session) -> Investigation:
    item = db.scalar(select(Investigation).where(Investigation.id == investigation_id, Investigation.owner_id == user.id))
    if not item: raise HTTPException(status_code=404, detail="Investigation not found")
    return item

@app.get("/api/health")
def health():
    return {"status": "ok", "app": "TraceForge", "version": app.version}

@app.post("/api/auth/register", status_code=201)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    email = str(payload.email).lower().strip()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    name = payload.display_name.strip()
    if len(name) < 2: raise HTTPException(status_code=422, detail="Display name must contain at least 2 characters")
    user = User(email=email, display_name=name, password_hash=hash_password(payload.password), max_upload_mb=MAX_UPLOAD_MB)
    db.add(user); db.commit(); db.refresh(user)
    audit(db, user.id, "account_created", "account"); db.commit()
    # A starter investigation makes first-run upload flow discoverable, not a fake finding/counter.
    case = Investigation(owner_id=user.id, title="Initial investigation", description="Starter case; rename or create another case when ready")
    db.add(case); db.commit()
    return {"access_token": create_access_token(user.id), "token_type": "bearer", "user": {"id": user.id, "email": user.email, "display_name": user.display_name}}

@app.post("/api/auth/login")
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == str(payload.email).lower().strip()))
    if not user or not verify_password(payload.password, user.password_hash):
        if user is not None:
            audit(db, user.id, "login_failed", "account", "denied")
            db.commit()
        raise HTTPException(status_code=401, detail="Email or password is incorrect")
    audit(db, user.id, "login", "account"); db.commit()
    return {"access_token": create_access_token(user.id), "token_type": "bearer", "user": {"id": user.id, "email": user.email, "display_name": user.display_name}}

@app.get("/api/me")
def me(user: User = Depends(current_user)):
    return {"id": user.id, "email": user.email, "display_name": user.display_name, "display_timezone": user.display_timezone, "created_at": iso(user.created_at)}

@app.get("/api/investigations")
def list_investigations(user: User = Depends(current_user), db: Session = Depends(get_db)):
    cases = db.scalars(select(Investigation).where(Investigation.owner_id == user.id).order_by(desc(Investigation.updated_at))).all()
    return [investigation_dict(c, db.scalar(select(func.count(Evidence.id)).where(Evidence.investigation_id == c.id, Evidence.owner_id == user.id)) or 0) for c in cases]

@app.post("/api/investigations", status_code=201)
def create_investigation(payload: dict, user: User = Depends(current_user), db: Session = Depends(get_db)):
    title = str(payload.get("title", "")).strip()[:200]
    description = str(payload.get("description", "")).strip()[:4000]
    if len(title) < 3: raise HTTPException(status_code=422, detail="Investigation title must contain at least 3 characters")
    case = Investigation(owner_id=user.id, title=title, description=description)
    db.add(case); db.flush(); audit(db, user.id, "investigation_created", f"investigation:{case.id}"); db.commit(); db.refresh(case)
    return investigation_dict(case, 0)

@app.patch("/api/investigations/{investigation_id}")
def update_investigation(investigation_id: int, payload: dict, user: User = Depends(current_user), db: Session = Depends(get_db)):
    case = owned_investigation(investigation_id, user, db)
    if "title" in payload:
        title = str(payload["title"]).strip()[:200]
        if len(title) < 3: raise HTTPException(status_code=422, detail="Investigation title must contain at least 3 characters")
        case.title = title
    if "description" in payload: case.description = str(payload["description"]).strip()[:4000]
    if "status" in payload:
        if payload["status"] not in {"open", "reviewed", "closed"}: raise HTTPException(status_code=422, detail="Status must be open, reviewed, or closed")
        case.status = payload["status"]
    case.updated_at = datetime.now(timezone.utc); audit(db, user.id, "investigation_updated", f"investigation:{case.id}"); db.commit(); db.refresh(case)
    return investigation_dict(case)

@app.get("/api/dashboard")
def dashboard(user: User = Depends(current_user), db: Session = Depends(get_db)):
    evidence = db.scalars(select(Evidence).where(Evidence.owner_id == user.id).order_by(desc(Evidence.created_at))).all()
    total_events = db.scalar(select(func.count(Event.id)).join(Evidence).where(Evidence.owner_id == user.id, Evidence.status == "completed")) or 0
    findings = db.scalars(select(Finding).join(Evidence).where(Evidence.owner_id == user.id, Evidence.status == "completed")).all()
    counts = {level: sum(1 for f in findings if f.severity == level) for level in ("high", "medium", "info", "low")}
    return {"total_investigations": db.scalar(select(func.count(Investigation.id)).where(Investigation.owner_id == user.id)) or 0, "total_evidence": len(evidence), "total_events": total_events,
            "total_findings": len(findings), "high_findings": counts["high"],
            "processing_failures": sum(1 for e in evidence if e.status == "failed"),
            "recent_evidence": [evidence_dict(x) for x in evidence[:5]], "severity_counts": counts}

@app.post("/api/evidence/upload", status_code=201)
async def upload_evidence(file: UploadFile = File(...), investigation_id: int | None = Form(default=None), user: User = Depends(current_user), db: Session = Depends(get_db)):
    original_name = Path((file.filename or "upload.log").replace("\\", "/")).name.replace("\x00", "")[:255]
    extension = Path(original_name).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS: raise HTTPException(status_code=400, detail="Supported formats: .log, .txt, .csv, .json")
    content = await file.read(user.max_upload_mb * 1024 * 1024 + 1)
    await file.close()
    if not content: raise HTTPException(status_code=400, detail="The uploaded file is empty")
    if len(content) > user.max_upload_mb * 1024 * 1024: raise HTTPException(status_code=413, detail=f"File exceeds your {user.max_upload_mb} MB upload limit")
    digest = hashlib.sha256(content).hexdigest()
    duplicate = db.scalar(select(Evidence).where(Evidence.owner_id == user.id, Evidence.sha256 == digest, Evidence.status == "completed"))
    if duplicate: raise HTTPException(status_code=409, detail=f"This exact file already exists as evidence ID {duplicate.id}; duplicate upload was not created")
    if investigation_id is not None:
        case = owned_investigation(investigation_id, user, db)
    else:
        case = db.scalar(select(Investigation).where(Investigation.owner_id == user.id, Investigation.status == "open").order_by(Investigation.id))
        if not case:
            case = Investigation(owner_id=user.id, title="Imported evidence investigation")
            db.add(case); db.flush()
    stored_name = f"{uuid.uuid4().hex}{extension}"
    target = UPLOAD_DIR / stored_name
    item = None
    try:
        target.write_bytes(content)
        item = Evidence(owner_id=user.id, investigation_id=case.id, original_name=original_name, stored_name=stored_name,
                        size_bytes=len(content), sha256=digest, status="processing")
        db.add(item); db.commit(); db.refresh(item)
        events, gaps = parse_log(content, original_name)
        event_rows = [Event(evidence_id=item.id, **event) for event in events]
        db.add_all(event_rows); db.flush()
        # Findings refer to persisted Event IDs, never temporary list positions.
        findings = analyse_events(events, user.alert_threshold)
        for finding in findings:
            source_indices = finding.pop("event_ids", [])
            finding["event_ids"] = json.dumps([event_rows[i].id for i in source_indices if 0 <= i < len(event_rows)])
            db.add(Finding(evidence_id=item.id, **finding))
        item.event_count = len(events); item.finding_count = len(findings); item.parsing_gaps = gaps; item.status = "completed"
        case.updated_at = datetime.now(timezone.utc)
        audit(db, user.id, "evidence_uploaded_and_analysed", f"evidence:{item.id}")
        db.commit(); db.refresh(item)
        return evidence_dict(item)
    except HTTPException:
        db.rollback()
        if target.exists(): target.unlink(missing_ok=True)
        raise
    except ValueError as exc:
        # Expected parser validation failures (for example, binary content disguised as .log)
        # are reported as client errors. Preserve the original bytes/hash and mark the record failed.
        db.rollback()
        failed = db.get(Evidence, item.id) if item is not None and item.id is not None else None
        if failed is not None:
            failed.status = "failed"
            failed.error_message = str(exc)[:500]
            audit(db, user.id, "evidence_format_rejected", f"evidence:{failed.id}", "failed")
            db.commit()
        else:
            if target.exists(): target.unlink(missing_ok=True)
            audit(db, user.id, "evidence_format_rejected", original_name, "failed"); db.commit()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        db.rollback()
        logger.exception("Evidence processing failed for an upload")
        failed = db.get(Evidence, item.id) if item is not None and item.id is not None else None
        if failed is not None:
            # Retain the original bytes and intake hash, but never retain partial parsed rows.
            failed.status = "failed"
            failed.error_message = "Processing failed. The original upload and intake hash were retained; parsed results are unavailable."
            audit(db, user.id, "evidence_processing_failed", f"evidence:{failed.id}", "failed")
            db.commit()
        else:
            if target.exists(): target.unlink(missing_ok=True)
            audit(db, user.id, "evidence_intake_failed", original_name, "failed"); db.commit()
        raise HTTPException(status_code=500, detail="Evidence processing failed. The original upload was retained if intake completed; check server logs.") from exc

@app.get("/api/evidence")
def list_evidence(investigation_id: int | None = None, user: User = Depends(current_user), db: Session = Depends(get_db)):
    query = select(Evidence).where(Evidence.owner_id == user.id)
    if investigation_id is not None:
        owned_investigation(investigation_id, user, db)
        query = query.where(Evidence.investigation_id == investigation_id)
    items = db.scalars(query.order_by(desc(Evidence.created_at))).all()
    return [evidence_dict(x) for x in items]

@app.get("/api/evidence/{evidence_id}")
def evidence_detail(evidence_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    item = owned_evidence(evidence_id, user, db)
    events = db.scalars(select(Event).where(Event.evidence_id == item.id).order_by(Event.timestamp.is_(None), Event.timestamp, Event.line_number)).all()
    findings = db.scalars(select(Finding).where(Finding.evidence_id == item.id).order_by(Finding.id)).all()
    return {"evidence": evidence_dict(item), "events": [{"id": e.id, "timestamp": e.timestamp, "event_type": e.event_type, "source_ip": e.source_ip, "username": e.username, "severity": e.severity, "message": e.message, "line_number": e.line_number} for e in events], "findings": [finding_dict(f) for f in findings]}

@app.get("/api/evidence/{evidence_id}/original-download")
def download_original_evidence(evidence_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Return the retained original upload only after an ownership check and audit entry."""
    item = owned_evidence(evidence_id, user, db)
    path = UPLOAD_DIR / item.stored_name
    if not path.is_file():
        audit(db, user.id, "original_evidence_download", f"evidence:{item.id}", "missing")
        db.commit()
        raise HTTPException(status_code=404, detail="Stored original evidence is missing")
    audit(db, user.id, "original_evidence_download", f"evidence:{item.id}")
    db.commit()
    return FileResponse(path, filename=item.original_name, media_type="application/octet-stream",
                        headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"})

@app.get("/api/evidence/{evidence_id}/verify")
def verify_evidence(evidence_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    item = owned_evidence(evidence_id, user, db); path = UPLOAD_DIR / item.stored_name
    if not path.is_file():
        audit(db, user.id, "evidence_hash_verification", f"evidence:{item.id}", "missing"); db.commit()
        return {"evidence_id": item.id, "verified": False, "message": "Stored file is missing"}
    digest = hashlib.sha256(path.read_bytes()).hexdigest(); match = digest == item.sha256
    audit(db, user.id, "evidence_hash_verification", f"evidence:{item.id}", "match" if match else "mismatch"); db.commit()
    return {"evidence_id": item.id, "verified": match, "reference_sha256": item.sha256, "current_sha256": digest,
            "message": "Hash matches the upload-time reference" if match else "Hash differs from the upload-time reference; investigate"}

def report_payload(item: Evidence, db: Session):
    events = db.scalars(select(Event).where(Event.evidence_id == item.id).order_by(Event.timestamp.is_(None), Event.timestamp, Event.line_number)).all()
    findings = db.scalars(select(Finding).where(Finding.evidence_id == item.id).order_by(Finding.id)).all()
    return {"report_title": "TraceForge Digital Evidence Analysis Report", "generated_at": datetime.now(timezone.utc).isoformat(),
            "timezone": "UTC; timestamps without explicit offsets are interpreted as UTC by the parser",
            "methodology": "Supported-format parsing and transparent deterministic rules; not an automated forensic verdict.",
            "limitations": ["A rule match is an indicator for review, not proof of malicious activity.", "SHA-256 verification compares current stored bytes to the hash recorded at upload; it does not prove source authenticity or complete chain of custody.", "Parser coverage is limited to documented supported formats; unrecognized fields or formats may be missed."],
            "investigation": {"id": item.investigation.id if item.investigation else None, "title": item.investigation.title if item.investigation else None},
            "evidence": evidence_dict(item), "processing": {"status": item.status, "parsed_events": len(events), "findings": len(findings), "parsing_gaps": item.parsing_gaps},
            "events": [{"id": e.id, "timestamp_utc": e.timestamp, "event_type": e.event_type, "severity": e.severity, "username": e.username, "source_ip": e.source_ip, "line_number": e.line_number, "message": e.message} for e in events],
            "findings": [finding_dict(f) for f in findings]}

def safe_csv_cell(value):
    if value is None: return ""
    value = str(value)
    # Prevent spreadsheet formula execution when opening exported logs in office software.
    if value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")): return "'" + value
    return value

def build_pdf(report: dict) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=18*mm, leftMargin=18*mm, topMargin=20*mm, bottomMargin=18*mm, title=report["report_title"], author="TraceForge")
    # Use ReportLab's bundled Vera font for broader Unicode support than built-in Helvetica.
    font_dir = Path(reportlab.__file__).resolve().parent / "fonts"
    if "TraceForgeSans" not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont("TraceForgeSans", str(font_dir / "Vera.ttf")))
        pdfmetrics.registerFont(TTFont("TraceForgeSans-Bold", str(font_dir / "VeraBd.ttf")))
    styles = getSampleStyleSheet()
    styles["BodyText"].fontName = "TraceForgeSans"
    styles["Heading2"].fontName = "TraceForgeSans-Bold"
    styles["Heading3"].fontName = "TraceForgeSans-Bold"
    styles.add(ParagraphStyle(name="TFTitle", parent=styles["Title"], fontName="TraceForgeSans-Bold", fontSize=23, leading=28, textColor=colors.HexColor("#172554"), alignment=TA_LEFT, spaceAfter=8))
    styles.add(ParagraphStyle(name="TFSection", parent=styles["Heading2"], fontSize=13, leading=17, textColor=colors.HexColor("#1D4ED8"), spaceBefore=12, spaceAfter=6, keepWithNext=True))
    styles.add(ParagraphStyle(name="TFBody", parent=styles["BodyText"], fontName="TraceForgeSans", fontSize=8.5, leading=12, spaceAfter=5, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="TFTiny", parent=styles["BodyText"], fontName="TraceForgeSans", fontSize=7, leading=9, textColor=colors.HexColor("#475569"), wordWrap="CJK"))
    def p(value, style="TFBody"):
        safe = str(value if value is not None else "—")
        safe = safe.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return Paragraph(safe.replace("\n", "<br/>"), styles[style])
    story = [Spacer(1, 22*mm), p("TRACEFORGE", "TFTitle"), p("DIGITAL EVIDENCE ANALYSIS REPORT", "Heading2"), Spacer(1, 5*mm), p("Structured review of uploaded log evidence", "TFBody"), Spacer(1, 8*mm)]
    case = report.get("investigation") or {}
    evidence = report["evidence"]
    summary = [[p("Report generated (UTC)"), p(report["generated_at"])], [p("Investigation"), p(f"{case.get('title') or 'Unassigned'} (ID {case.get('id') or '—'})")], [p("Evidence record"), p(f"{evidence['filename']} (ID {evidence['id']})")], [p("Processing status"), p(report["processing"]["status"])], [p("Parsed events / findings / gaps"), p(f"{report['processing']['parsed_events']} / {report['processing']['findings']} / {report['processing']['parsing_gaps']}")], [p("SHA-256 upload reference"), p(evidence["sha256"], "TFTiny")]]
    table = Table(summary, colWidths=[48*mm, 112*mm], repeatRows=0)
    table.setStyle(TableStyle([("BACKGROUND",(0,0),(0,-1),colors.HexColor("#F1F5F9")),("GRID",(0,0),(-1,-1),0.35,colors.HexColor("#CBD5E1")),("VALIGN",(0,0),(-1,-1),"TOP"),("LEFTPADDING",(0,0),(-1,-1),7),("RIGHTPADDING",(0,0),(-1,-1),7),("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6)]))
    story += [table, Spacer(1, 8*mm), p("Purpose and interpretation", "TFSection"), p("This report records the output of supported-format parsing and deterministic pattern rules. Findings are triage leads for review, not proof of compromise, intent, or attribution."), Spacer(1, 8*mm), p("Generated by TraceForge · AIORI-3 PS-013", "TFTiny"), PageBreak(), p("Executive summary", "TFSection"), p(f"This report documents analysis of {report['processing']['parsed_events']} parsed events from one uploaded evidence file. The rules generated {report['processing']['findings']} finding(s). These are review leads based on recognizable log patterns, not a determination that a system was compromised. {report['processing']['parsing_gaps']} parsing gap(s) were recorded; review the source file where completeness matters.")]
    story += [p("Scope and method", "TFSection"), p("The uploaded file was hashed with SHA-256 at intake, parsed using the documented TraceForge parser, and reviewed with deterministic pattern rules. Timestamps are normalized to UTC when recognized. Naive timestamps are interpreted as UTC; missing timestamps are not fabricated.")]
    story += [p("Evidence inventory and integrity", "TFSection"), p(f"Original filename: {evidence['filename']}"), p(f"Evidence ID: {evidence['id']} · Size: {evidence['size_bytes']} bytes · Uploaded: {evidence['created_at']}"), p(f"SHA-256 upload reference: {evidence['sha256']}", "TFTiny"), p("A matching verification indicates the stored bytes match the upload-time reference only. It does not prove the source was authentic or establish a full chain of custody.")]
    story += [p("Findings", "TFSection")]
    findings = report["findings"]
    if not findings: story.append(p("No configured detection rule triggered for this evidence. This is not a guarantee that the logs are safe; rule coverage is intentionally limited."))
    for f in findings:
        # Avoid a single enormous paragraph for findings linked to thousands of events.
        # The PDF shows representative IDs; the complete mapping remains in JSON/CSV exports.
        linked_ids = f.get("event_ids", [])
        visible_ids = ", ".join(map(str, linked_ids[:100])) or "None"
        if len(linked_ids) > 100:
            visible_ids += f" … and {len(linked_ids) - 100} more (see structured export)"
        story.append(KeepTogether([p(f"{f['severity'].upper()} · {f['title']} · {f['rule_id']}", "Heading3"), p(f["description"]), p(f"Rule rationale: {f['rationale']}"), p(f"Linked event IDs (first 100): {visible_ids}"), p(f"Event count: {f['event_count']} · Time range: {f.get('start_timestamp') or 'unknown'} to {f.get('end_timestamp') or 'unknown'}"), p(f"Recommended review: {f['recommended_action']}")]))
    story += [p("Event timeline (chronological)", "TFSection")]
    event_rows = [[p("Event ID", "TFTiny"), p("UTC timestamp", "TFTiny"), p("Type", "TFTiny"), p("Severity", "TFTiny"), p("Line", "TFTiny"), p("Event", "TFTiny")]]
    for e in report["events"]:
        event_rows.append([p(e["id"], "TFTiny"), p(e["timestamp_utc"] or "Unknown", "TFTiny"), p(e["event_type"], "TFTiny"), p(e["severity"], "TFTiny"), p(e["line_number"], "TFTiny"), p(e["message"][:450], "TFTiny")])
    if len(event_rows) == 1: event_rows.append([p("—", "TFTiny"), p("No events parsed", "TFTiny"), p("—", "TFTiny"), p("—", "TFTiny"), p("—", "TFTiny"), p("Review parsing gaps and the original file", "TFTiny")])
    event_table = Table(event_rows, colWidths=[10*mm, 36*mm, 31*mm, 16*mm, 12*mm, 65*mm], repeatRows=1)
    event_table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#E2E8F0")),("GRID",(0,0),(-1,-1),0.25,colors.HexColor("#CBD5E1")),("VALIGN",(0,0),(-1,-1),"TOP"),("LEFTPADDING",(0,0),(-1,-1),4),("RIGHTPADDING",(0,0),(-1,-1),4),("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4)]))
    story.append(event_table)
    story += [p("Limitations and recommended use", "TFSection")]
    for limitation in report["limitations"]: story.append(p("• " + limitation))
    story.append(p("Use this report as a structured triage record. Preserve the original evidence, document collection context separately, and corroborate findings with system-owner knowledge and additional sources.", "TFBody"))
    def footer(canvas, doc):
        canvas.saveState(); canvas.setStrokeColor(colors.HexColor("#CBD5E1")); canvas.line(18*mm, 13*mm, A4[0]-18*mm, 13*mm)
        canvas.setFont("TraceForgeSans", 7); canvas.setFillColor(colors.HexColor("#64748B")); canvas.drawString(18*mm, 8*mm, "TraceForge · Educational incident-investigation support")
        canvas.drawRightString(A4[0]-18*mm, 8*mm, f"Page {doc.page}"); canvas.restoreState()
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()

def persist_report(user: User, item: Evidence, fmt: str, filename: str, content: bytes, db: Session, dataset: str = "all"):
    stored = f"{uuid.uuid4().hex}.{fmt}"
    path = REPORT_DIR / stored
    path.write_bytes(content)
    report = Report(owner_id=user.id, evidence_id=item.id, investigation_id=item.investigation_id,
                    format=(f"csv-{dataset}" if fmt == "csv" and dataset != "all" else fmt), filename=filename, stored_name=stored)
    try:
        db.add(report); audit(db, user.id, f"report_generated_{fmt}", f"evidence:{item.id}"); db.commit(); db.refresh(report)
        return report
    except Exception:
        db.rollback(); path.unlink(missing_ok=True)
        raise

@app.post("/api/evidence/{evidence_id}/reports/{fmt}")
def generate_report(evidence_id: int, fmt: str, dataset: str = "all", user: User = Depends(current_user), db: Session = Depends(get_db)):
    if fmt not in {"pdf", "json", "csv"}: raise HTTPException(status_code=400, detail="Supported report formats: pdf, json, csv")
    if dataset not in {"all", "events", "findings", "evidence"}: raise HTTPException(status_code=400, detail="CSV dataset must be all, events, findings, or evidence")
    if fmt != "csv" and dataset != "all": raise HTTPException(status_code=400, detail="Dataset selection is available only for CSV exports")
    item = owned_evidence(evidence_id, user, db)
    if item.status != "completed": raise HTTPException(status_code=409, detail="Reports are available only for successfully processed evidence")
    try:
        data = report_payload(item, db)
        if fmt == "pdf":
            content = build_pdf(data); filename = f"TraceForge-evidence-{item.id}-report.pdf"; media = "application/pdf"
        elif fmt == "json":
            content = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8"); filename = f"TraceForge-evidence-{item.id}-report.json"; media = "application/json"
        else:
            buffer = io.StringIO(newline=""); writer = csv.writer(buffer)
            if dataset in {"all", "events"}:
                writer.writerow(["event_id", "timestamp_utc", "event_type", "severity", "source_ip", "username", "line_number", "message"])
                for e in data["events"]: writer.writerow([e["id"], safe_csv_cell(e["timestamp_utc"] or ""), safe_csv_cell(e["event_type"]), safe_csv_cell(e["severity"]), safe_csv_cell(e["source_ip"]), safe_csv_cell(e["username"]), e["line_number"], safe_csv_cell(e["message"])])
            if dataset == "findings":
                writer.writerow(["finding_id", "rule_id", "severity", "title", "description", "event_count", "linked_event_ids", "start_timestamp_utc", "end_timestamp_utc", "rationale", "recommended_action"])
                for f in data["findings"]: writer.writerow([f["id"], f["rule_id"], f["severity"], safe_csv_cell(f["title"]), safe_csv_cell(f["description"]), f["event_count"], safe_csv_cell(",".join(map(str, f["event_ids"]))), f["start_timestamp"] or "", f["end_timestamp"] or "", safe_csv_cell(f["rationale"]), safe_csv_cell(f["recommended_action"])])
            elif dataset == "evidence":
                writer.writerow(["evidence_id", "investigation_id", "investigation_title", "filename", "size_bytes", "sha256_upload_reference", "status", "parsed_event_count", "finding_count", "parsing_gaps", "uploaded_at_utc"])
                e = data["evidence"]
                writer.writerow([e["id"], e["investigation_id"] or "", safe_csv_cell(e["investigation_title"]), safe_csv_cell(e["filename"]), e["size_bytes"], e["sha256"], e["status"], e["event_count"], e["finding_count"], e["parsing_gaps"], e["created_at"]])
            content = buffer.getvalue().encode("utf-8-sig")
            suffix = "report" if dataset == "all" else dataset
            filename = f"TraceForge-evidence-{item.id}-{suffix}.csv"; media = "text/csv; charset=utf-8"
        report = persist_report(user, item, fmt, filename, content, db, dataset)
    except HTTPException:
        raise
    except Exception as exc:
        db.rollback(); logger.exception("Report generation failed")
        audit(db, user.id, "report_generation_failed", f"evidence:{item.id}", "failed"); db.commit()
        raise HTTPException(status_code=500, detail="Report generation failed and was recorded in the audit trail") from exc
    return {"report_id": report.id, "filename": filename, "format": report.format, "download_url": f"/api/reports/{report.id}/download", "size_bytes": len(content), "media_type": media}

@app.post("/api/evidence/{evidence_id}/export-package")
# Keep the default PDF action simple; place machine-readable exports together in one optional package.
def export_investigation_package(evidence_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Build one convenient ZIP containing the PDF report and machine-readable exports."""
    item = owned_evidence(evidence_id, user, db)
    if item.status != "completed":
        raise HTTPException(status_code=409, detail="Export packages require successfully processed evidence")
    try:
        data = report_payload(item, db)
        pdf_bytes = build_pdf(data)
        json_bytes = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
        # Use CSV-safe cells for every untrusted text field to reduce spreadsheet formula injection risk.
        csv_outputs = {}
        events_io = io.StringIO(newline=""); writer = csv.writer(events_io)
        writer.writerow(["event_id", "timestamp_utc", "event_type", "severity", "source_ip", "username", "line_number", "message"])
        for event in data["events"]:
            writer.writerow([event["id"], safe_csv_cell(event["timestamp_utc"] or ""), safe_csv_cell(event["event_type"]), safe_csv_cell(event["severity"]), safe_csv_cell(event["source_ip"]), safe_csv_cell(event["username"]), event["line_number"], safe_csv_cell(event["message"])])
        csv_outputs["events.csv"] = events_io.getvalue().encode("utf-8-sig")
        findings_io = io.StringIO(newline=""); writer = csv.writer(findings_io)
        writer.writerow(["finding_id", "rule_id", "severity", "title", "description", "event_count", "linked_event_ids", "start_timestamp_utc", "end_timestamp_utc", "rationale", "recommended_action"])
        for finding in data["findings"]:
            writer.writerow([finding["id"], finding["rule_id"], finding["severity"], safe_csv_cell(finding["title"]), safe_csv_cell(finding["description"]), finding["event_count"], safe_csv_cell(",".join(map(str, finding["event_ids"]))), finding["start_timestamp"] or "", finding["end_timestamp"] or "", safe_csv_cell(finding["rationale"]), safe_csv_cell(finding["recommended_action"])])
        csv_outputs["findings.csv"] = findings_io.getvalue().encode("utf-8-sig")
        evidence_io = io.StringIO(newline=""); writer = csv.writer(evidence_io)
        writer.writerow(["evidence_id", "investigation_id", "investigation_title", "filename", "size_bytes", "sha256_upload_reference", "status", "parsed_event_count", "finding_count", "parsing_gaps", "uploaded_at_utc"])
        ev = data["evidence"]
        writer.writerow([ev["id"], ev["investigation_id"] or "", safe_csv_cell(ev["investigation_title"]), safe_csv_cell(ev["filename"]), ev["size_bytes"], ev["sha256"], ev["status"], ev["event_count"], ev["finding_count"], ev["parsing_gaps"], ev["created_at"]])
        csv_outputs["evidence-inventory.csv"] = evidence_io.getvalue().encode("utf-8-sig")
        manifest = {"product":"TraceForge", "package_version":1, "generated_at_utc":data["generated_at"], "evidence_id":item.id,
                    "evidence_sha256_upload_reference":item.sha256, "files":{ "investigation-report.pdf":hashlib.sha256(pdf_bytes).hexdigest(), "investigation.json":hashlib.sha256(json_bytes).hexdigest(), **{name:hashlib.sha256(content).hexdigest() for name,content in csv_outputs.items()} },
                    "note":"Hashes identify files in this export package; this manifest is not digitally signed and is not a complete chain-of-custody record."}
        buffer=io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("investigation-report.pdf", pdf_bytes)
            archive.writestr("investigation.json", json_bytes)
            for name, content in csv_outputs.items(): archive.writestr(name, content)
            archive.writestr("manifest.json", json.dumps(manifest, indent=2).encode("utf-8"))
        content=buffer.getvalue(); filename=f"TraceForge-investigation-{item.id}-package.zip"
        report=persist_report(user,item,"zip",filename,content,db)
    except Exception as exc:
        db.rollback(); logger.exception("Investigation package generation failed")
        audit(db,user.id,"report_generation_failed",f"evidence:{item.id}","failed"); db.commit()
        raise HTTPException(status_code=500, detail="Export package generation failed and was recorded") from exc
    return {"report_id":report.id,"filename":filename,"format":"zip","download_url":f"/api/reports/{report.id}/download","size_bytes":len(content),"media_type":"application/zip"}

@app.get("/api/search")
# Search is performed server-side so the browser never needs to download the full event corpus.
def search_events(q: str = "", investigation_id: int | None = None, severity: str | None = None,
                 event_type: str | None = None, page: int = 1, page_size: int = 50,
                 user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Search structured events only within the authenticated user's evidence."""
    if page < 1: raise HTTPException(status_code=422, detail="Page must be at least 1")
    if page_size < 1 or page_size > 100: raise HTTPException(status_code=422, detail="Page size must be between 1 and 100")
    if severity and severity not in {"high", "medium", "low", "info"}: raise HTTPException(status_code=422, detail="Unsupported severity")
    query=select(Event, Evidence).join(Evidence, Event.evidence_id==Evidence.id).where(Evidence.owner_id==user.id, Evidence.status=="completed")
    if investigation_id is not None:
        owned_investigation(investigation_id,user,db); query=query.where(Evidence.investigation_id==investigation_id)
    if severity: query=query.where(Event.severity==severity)
    if event_type: query=query.where(Event.event_type==event_type[:100])
    needle=q.strip()[:200]
    if needle:
        like=f"%{needle.replace('%', r'\\%').replace('_', r'\\_')}%"
        text_match=(Event.message.ilike(like, escape="\\")) | (Event.source_ip.ilike(like, escape="\\")) | (Event.username.ilike(like, escape="\\")) | (Event.event_type.ilike(like, escape="\\"))
        if needle.isdigit(): text_match = text_match | (Event.id == int(needle))
        query=query.where(text_match)
    total=db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows=db.execute(query.order_by(Event.timestamp.is_(None),Event.timestamp,Event.id).offset((page-1)*page_size).limit(page_size)).all()
    return {"query":needle,"page":page,"page_size":page_size,"total":total,"pages":(total+page_size-1)//page_size,
            "results":[{"event_id":event.id,"evidence_id":evidence.id,"filename":evidence.original_name,"investigation_id":evidence.investigation_id,
                        "timestamp_utc":event.timestamp,"event_type":event.event_type,"severity":event.severity,"source_ip":event.source_ip,
                        "username":event.username,"line_number":event.line_number,"message":event.message} for event,evidence in rows]}

@app.get("/api/reports")
def list_reports(user: User = Depends(current_user), db: Session = Depends(get_db)):
    reports = db.scalars(select(Report).where(Report.owner_id == user.id).order_by(desc(Report.created_at))).all()
    return [{"id": r.id, "evidence_id": r.evidence_id, "investigation_id": r.investigation_id, "format": r.format, "filename": r.filename, "created_at": iso(r.created_at), "download_url": f"/api/reports/{r.id}/download"} for r in reports]

@app.get("/api/reports/{report_id}/download")
def download_report(report_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    report = db.scalar(select(Report).where(Report.id == report_id, Report.owner_id == user.id))
    if not report: raise HTTPException(status_code=404, detail="Report not found")
    path = REPORT_DIR / report.stored_name
    if not path.is_file(): raise HTTPException(status_code=410, detail="Report file is no longer available")
    audit(db, user.id, "report_downloaded", f"report:{report.id}"); db.commit()
    return FileResponse(path, filename=report.filename, media_type={"pdf":"application/pdf", "json":"application/json", "zip":"application/zip"}.get(report.format, "text/csv" if report.format.startswith("csv") else "application/octet-stream"))

@app.get("/api/history")
def history(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Investigation history: real cases, evidence records and saved reports, not login/debug logs."""
    entries = []
    cases = db.scalars(select(Investigation).where(Investigation.owner_id == user.id)).all()
    for case in cases:
        entries.append({"kind": "Investigation", "action": f"{case.status.title()} investigation", "target": case.title,
                        "details": f"Case ID {case.id} · {db.scalar(select(func.count(Evidence.id)).where(Evidence.investigation_id == case.id, Evidence.owner_id == user.id)) or 0} evidence file(s)",
                        "outcome": case.status, "created_at": iso(case.updated_at or case.created_at)})
    evidence_items = db.scalars(select(Evidence).where(Evidence.owner_id == user.id)).all()
    for item in evidence_items:
        entries.append({"kind": "Evidence", "action": "Evidence processed" if item.status == "completed" else f"Evidence {item.status}",
                        "target": item.original_name, "details": f"Evidence ID {item.id} · {item.event_count} event(s) · {item.finding_count} finding(s) · {item.size_bytes} bytes · SHA-256 {item.sha256}",
                        "outcome": item.status, "created_at": iso(item.created_at)})
    reports = db.scalars(select(Report).where(Report.owner_id == user.id)).all()
    for report in reports:
        entries.append({"kind": "Report", "action": f"{report.format.replace('csv-', 'CSV · ').upper()} report generated", "target": report.filename,
                        "details": f"Report ID {report.id} · Evidence ID {report.evidence_id}", "outcome": "saved", "created_at": iso(report.created_at)})
    # Include integrity verification events only; routine sign-in and settings records remain in /api/audit.
    checks = db.scalars(select(AuditLog).where(AuditLog.owner_id == user.id, AuditLog.action == "evidence_hash_verification")).all()
    for check in checks:
        entries.append({"kind": "Integrity check", "action": "SHA-256 verification", "target": check.target,
                        "details": "Hash verification result recorded", "outcome": check.outcome, "created_at": iso(check.created_at)})
    entries.sort(key=lambda entry: entry["created_at"] or "", reverse=True)
    return entries[:300]

@app.get("/api/audit")
def audit_history(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Restricted-to-owner audit records, separate from investigation history."""
    entries = db.scalars(select(AuditLog).where(AuditLog.owner_id == user.id).order_by(desc(AuditLog.created_at)).limit(300)).all()
    return [{"id": e.id, "action": e.action, "target": e.target, "outcome": e.outcome, "created_at": iso(e.created_at)} for e in entries]

@app.get("/api/settings")
def get_settings(user: User = Depends(current_user)):
    return {"display_name": user.display_name, "email": user.email, "max_upload_mb": user.max_upload_mb, "alert_threshold": user.alert_threshold, "display_timezone": user.display_timezone}

@app.put("/api/settings")
def update_settings(payload: SettingsRequest, user: User = Depends(current_user), db: Session = Depends(get_db)):
    name = payload.display_name.strip()
    if len(name) < 2: raise HTTPException(status_code=422, detail="Display name must contain at least 2 characters")
    user.display_name = name; user.max_upload_mb = payload.max_upload_mb; user.alert_threshold = payload.alert_threshold; user.display_timezone = payload.display_timezone
    audit(db, user.id, "settings_updated", "account settings"); db.commit(); db.refresh(user)
    return get_settings(user)
