from pydantic import BaseModel
from typing import Optional, List, Dict, Any

class ClassifierLog(BaseModel):
    timestamp: str
    pid: int
    process: str
    current_kbps: float
    avg_kbps: float
    classification: str
    severity: int
    resolved_host: Optional[str] = None

class DegradationAlert(BaseModel):
    timestamp: str
    pid: int
    process: str
    app_class: str
    severity: int
    current_kbps: float
    baseline_kbps: float
    degraded_calls: int
    reason: str

class RootCauseLog(BaseModel):
    timestamp: str
    pid: int
    process: str
    app_class: str
    severity: int
    cause: str
    confidence: float
    secondary_cause: Optional[str] = None
    evidence: Optional[str] = None
    recommendation: Optional[str] = None
    rtt_ms: Optional[float] = None
    jitter_ms: Optional[float] = None
    rtt_baseline_ms: Optional[float] = None
    rtt_jump: Optional[bool] = None
    rtt_sustained: Optional[bool] = None
    retransmit_rate: Optional[float] = None
    dns_ms: Optional[float] = None
    wifi_pct: Optional[float] = None
    cpu_pct: Optional[float] = None

class WsRootCause(BaseModel):
    app: str
    kbps: float
    severity: int
    cause: str
    confidence: float
    recommendation: str

class WsSignals(BaseModel):
    rtt: float
    wifi: float
    cpu: float

class WsPayload(BaseModel):
    flows: List[Dict[str, Any]]
    root_causes: List[WsRootCause]
    signals: WsSignals

class HistoryResponse(BaseModel):
    data: List[Any]
    total: int
    page: int
    size: int
