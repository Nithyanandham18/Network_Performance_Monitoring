"""
database.py — SQLite/SQLAlchemy database layer for NetPulse
Stores classifier logs, degradation alerts, root cause analyses, and signal snapshots.
"""

import os
from datetime import datetime
from sqlalchemy import (
    create_engine, Column, Integer, Float, String, Boolean, DateTime, Text
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from sqlalchemy import inspect as sa_inspect

DB_PATH = os.path.join(os.path.dirname(__file__), "netpulse.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ── ORM Models ──────────────────────────────────────────────────────────────

class ClassifierLog(Base):
    __tablename__ = "classifier_logs"

    id             = Column(Integer, primary_key=True, index=True)
    timestamp      = Column(DateTime, default=datetime.utcnow, index=True)
    pid            = Column(Integer)
    process        = Column(String(64))
    current_kbps   = Column(Float)
    avg_kbps       = Column(Float)
    classification = Column(String(128))
    severity       = Column(Integer)
    resolved_host  = Column(String(256), nullable=True)


class DegradationAlert(Base):
    __tablename__ = "degradation_alerts"

    id             = Column(Integer, primary_key=True, index=True)
    timestamp      = Column(DateTime, default=datetime.utcnow, index=True)
    pid            = Column(Integer)
    process        = Column(String(64))
    app_class      = Column(String(128))
    severity       = Column(Integer)
    current_kbps   = Column(Float)
    baseline_kbps  = Column(Float)
    degraded_calls = Column(Integer)
    reason         = Column(Text)


class RootCauseLog(Base):
    __tablename__ = "root_cause_logs"

    id              = Column(Integer, primary_key=True, index=True)
    timestamp       = Column(DateTime, default=datetime.utcnow, index=True)
    pid             = Column(Integer)
    process         = Column(String(64))
    app_class       = Column(String(128))
    severity        = Column(Integer)
    cause           = Column(String(256))
    confidence      = Column(Float)
    secondary_cause = Column(String(256), nullable=True)
    evidence        = Column(Text, nullable=True)
    recommendation  = Column(Text, nullable=True)
    rtt_ms          = Column(Float, nullable=True)
    jitter_ms       = Column(Float, nullable=True)
    rtt_baseline_ms = Column(Float, nullable=True)
    rtt_jump        = Column(Boolean, nullable=True)
    rtt_sustained   = Column(Boolean, nullable=True)
    retransmit_rate = Column(Float, nullable=True)
    dns_ms          = Column(Float, nullable=True)
    wifi_pct        = Column(Float, nullable=True)
    cpu_pct         = Column(Float, nullable=True)


class SignalSnapshot(Base):
    __tablename__ = "signal_snapshots"

    id         = Column(Integer, primary_key=True, index=True)
    timestamp  = Column(DateTime, default=datetime.utcnow, index=True)
    rtt_ms     = Column(Float, nullable=True)
    jitter_ms  = Column(Float, nullable=True)
    wifi_pct   = Column(Float, nullable=True)
    dns_ms     = Column(Float, nullable=True)
    cpu_pct    = Column(Float)
    total_kbps = Column(Float)
    peak_kbps  = Column(Float)
    flow_count = Column(Integer)


# ── Init ─────────────────────────────────────────────────────────────────────

def init_db():
    """Create all tables if they don't exist."""
    Base.metadata.create_all(bind=engine)
    print(f"[DB] SQLite database ready at: {DB_PATH}")


def get_db() -> Session:
    """Dependency: yield a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Write helpers (called from background threads) ───────────────────────────

def db_write_classifier_row(row: dict):
    db = SessionLocal()
    try:
        db.add(ClassifierLog(
            timestamp=datetime.utcnow(),
            pid=row.get("pid"),
            process=row.get("proc", ""),
            current_kbps=row.get("kbps", 0.0),
            avg_kbps=row.get("avg_kbps", 0.0),
            classification=row.get("classification", ""),
            severity=row.get("severity", 0),
            resolved_host=row.get("hostname", ""),
        ))
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"[DB] classifier write error: {e}")
    finally:
        db.close()


def db_write_alert(alert):
    db = SessionLocal()
    try:
        db.add(DegradationAlert(
            timestamp=datetime.utcnow(),
            pid=alert.pid,
            process=alert.proc,
            app_class=alert.app_class,
            severity=alert.severity,
            current_kbps=alert.current_kbps,
            baseline_kbps=alert.baseline_kbps,
            degraded_calls=alert.degraded_secs,
            reason=alert.reason,
        ))
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"[DB] alert write error: {e}")
    finally:
        db.close()


def db_write_rootcause(rc):
    db = SessionLocal()
    try:
        db.add(RootCauseLog(
            timestamp=datetime.utcnow(),
            pid=rc.alert.pid,
            process=rc.alert.proc,
            app_class=rc.alert.app_class,
            severity=rc.alert.severity,
            cause=rc.cause,
            confidence=rc.confidence,
            recommendation=rc.recommendation,
            evidence="|".join(rc.evidence) if rc.evidence else "",
        ))
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"[DB] root cause write error: {e}")
    finally:
        db.close()


def db_write_signal_snapshot(snap, total_kbps: float, peak_kbps: float, flow_count: int):
    db = SessionLocal()
    try:
        db.add(SignalSnapshot(
            timestamp=datetime.utcnow(),
            rtt_ms=snap.rtt_ms if snap.rtt_ms >= 0 else None,
            jitter_ms=snap.jitter_ms if snap.jitter_ms >= 0 else None,
            wifi_pct=snap.wifi_signal_pct if snap.wifi_signal_pct >= 0 else None,
            dns_ms=snap.dns_ms if snap.dns_ms >= 0 else None,
            cpu_pct=snap.cpu_pct,
            total_kbps=total_kbps,
            peak_kbps=peak_kbps,
            flow_count=flow_count,
        ))
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"[DB] signal snapshot write error: {e}")
    finally:
        db.close()
