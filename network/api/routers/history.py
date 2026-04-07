"""
api/routers/history.py — SQL-backed history endpoints
All data is served from the SQLite database via SQLAlchemy.
"""
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from database import (
    get_db,
    ClassifierLog,
    DegradationAlert,
    RootCauseLog,
    SignalSnapshot,
)

router = APIRouter(prefix="/api/history", tags=["history"])


def paginate(query, page: int, size: int):
    total = query.count()
    items = query.offset((page - 1) * size).limit(size).all()
    return total, items


def row_to_dict(obj) -> dict:
    """Convert a SQLAlchemy ORM object to a plain dict."""
    d = {}
    for col in obj.__table__.columns:
        val = getattr(obj, col.name)
        if hasattr(val, "isoformat"):
            val = val.isoformat(sep=" ", timespec="seconds")
        d[col.name] = val
    return d


# ── Classifier Logs ──────────────────────────────────────────────────────────

@router.get("/classifier")
def get_classifier_history(
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
    process: Optional[str] = Query(None),
    min_severity: Optional[int] = Query(None),
    db: Session = Depends(get_db),
):
    """Fetch classifier logs from the SQL database with optional filters."""
    q = db.query(ClassifierLog).order_by(desc(ClassifierLog.timestamp))
    if process:
        q = q.filter(ClassifierLog.process.ilike(f"%{process}%"))
    if min_severity is not None:
        q = q.filter(ClassifierLog.severity >= min_severity)
    total, rows = paginate(q, page, size)
    return {"data": [row_to_dict(r) for r in rows], "total": total, "page": page, "size": size}


# ── Degradation Alerts ───────────────────────────────────────────────────────

@router.get("/alerts")
def get_alerts_history(
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
    min_severity: Optional[int] = Query(None),
    db: Session = Depends(get_db),
):
    """Fetch degradation alerts from the SQL database."""
    q = db.query(DegradationAlert).order_by(desc(DegradationAlert.timestamp))
    if min_severity is not None:
        q = q.filter(DegradationAlert.severity >= min_severity)
    total, rows = paginate(q, page, size)
    return {"data": [row_to_dict(r) for r in rows], "total": total, "page": page, "size": size}


# ── Root Cause Logs ──────────────────────────────────────────────────────────

@router.get("/root-causes")
def get_root_causes_history(
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
):
    """Fetch root cause analyses from the SQL database."""
    q = db.query(RootCauseLog).order_by(desc(RootCauseLog.timestamp))
    total, rows = paginate(q, page, size)
    return {"data": [row_to_dict(r) for r in rows], "total": total, "page": page, "size": size}


# ── Signal Snapshots ─────────────────────────────────────────────────────────

@router.get("/signals")
def get_signals_history(
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
):
    """Fetch 30-second signal snapshots from the SQL database."""
    q = db.query(SignalSnapshot).order_by(desc(SignalSnapshot.timestamp))
    total, rows = paginate(q, page, size)
    return {"data": [row_to_dict(r) for r in rows], "total": total, "page": page, "size": size}


# ── Stats Summary ────────────────────────────────────────────────────────────

@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    """Aggregate statistics from the SQL database."""
    clf_count  = db.query(func.count(ClassifierLog.id)).scalar()
    alert_count = db.query(func.count(DegradationAlert.id)).scalar()
    rc_count   = db.query(func.count(RootCauseLog.id)).scalar()
    snap_count = db.query(func.count(SignalSnapshot.id)).scalar()

    avg_rtt = db.query(func.avg(SignalSnapshot.rtt_ms)).filter(
        SignalSnapshot.rtt_ms.isnot(None)
    ).scalar()

    avg_cpu = db.query(func.avg(SignalSnapshot.cpu_pct)).scalar()

    max_sev = db.query(func.max(DegradationAlert.severity)).scalar()

    top_processes = (
        db.query(ClassifierLog.process, func.count(ClassifierLog.id).label("count"))
        .group_by(ClassifierLog.process)
        .order_by(desc("count"))
        .limit(5)
        .all()
    )

    cause_distribution = (
        db.query(RootCauseLog.cause, func.count(RootCauseLog.id).label("count"))
        .group_by(RootCauseLog.cause)
        .order_by(desc("count"))
        .limit(8)
        .all()
    )

    return {
        "total_classifier_logs": clf_count or 0,
        "total_alerts": alert_count or 0,
        "total_root_causes": rc_count or 0,
        "total_snapshots": snap_count or 0,
        "avg_rtt_ms": round(avg_rtt, 2) if avg_rtt else None,
        "avg_cpu_pct": round(avg_cpu, 2) if avg_cpu else None,
        "max_severity": max_sev or 0,
        "top_processes": [{"process": p, "count": c} for p, c in top_processes],
        "cause_distribution": [{"cause": c, "count": cnt} for c, cnt in cause_distribution],
    }


# ── Backward-compat: network (maps to signals) ───────────────────────────────

@router.get("/network")
def get_network_history(
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
):
    """Alias for /signals — backward compatibility."""
    q = db.query(SignalSnapshot).order_by(desc(SignalSnapshot.timestamp))
    total, rows = paginate(q, page, size)
    return {"data": [row_to_dict(r) for r in rows], "total": total, "page": page, "size": size}
