# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional

from pydantic import AliasChoices, BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SurgeMode(str, Enum):
    AUTONOMOUS = "AUTONOMOUS"
    CONTROLLED = "CONTROLLED"
    LOCKDOWN = "LOCKDOWN"
    ESCALATION_REQUIRED = "ESCALATION_REQUIRED"


class HealthResponse(BaseModel):
    status: str = "ok"
    service: str = "surge-operator-broker"
    environment: str
    database_target: str
    surge_core_mode: SurgeMode
    surge_core_reachable: bool = False
    tunnel_alive: bool = False
    ollama_reachable: bool = False
    uptime_seconds: float = 0.0


class SessionCreateRequest(BaseModel):
    client_type: str
    session_label: str = ""


class SessionResponse(BaseModel):
    session_id: str
    user_id: str
    client_type: str
    session_label: str = ""
    created_at: datetime = Field(default_factory=utc_now)


class ProjectCreateRequest(BaseModel):
    name: str
    tenant_id: Optional[str] = None
    local_path: Optional[str] = None
    remote_path: Optional[str] = None


class ProjectRecord(BaseModel):
    id: str
    name: str
    tenant_id: Optional[str] = None
    local_path: Optional[str] = None
    remote_path: Optional[str] = None
    created_at: datetime = Field(default_factory=utc_now)


class ExecuteCommandRequest(BaseModel):
    session_id: str
    tool_name: str
    payload: Dict[str, Any] = Field(default_factory=dict)


class ExecuteCommandResponse(BaseModel):
    request_id: str = ""
    status: str
    mode: SurgeMode
    approval_required: bool
    summary: str
    audit_event_id: str = ""


class AuditEventRecord(BaseModel):
    id: str
    actor_id: str
    action: str
    entity_type: str
    entity_id: str
    summary: str
    created_at: datetime


class AuthWhoAmIResponse(BaseModel):
    user_id: str
    token_label: str
    created_at: datetime = Field(default_factory=utc_now)


class ApprovalRecord(BaseModel):
    id: str
    session_id: str
    actor_id: str
    tool_name: str
    mode_at_submit: SurgeMode
    status: str
    summary: str
    payload: Dict[str, Any]
    surge_task_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class ApprovalDecisionRequest(BaseModel):
    decision_notes: str = ""


class TerminalSessionCreateRequest(BaseModel):
    session_id: str
    cwd: Optional[str] = None
    shell: str = "/bin/zsh"


class TerminalSessionRecord(BaseModel):
    id: str
    session_id: str
    cwd: str
    shell: str
    alive: bool


class TerminalInputRequest(BaseModel):
    input: str


class TerminalSnapshot(BaseModel):
    id: str
    session_id: str
    cwd: str
    shell: str
    alive: bool
    output: str


class ChatMessageRecord(BaseModel):
    id: str
    session_id: str
    role: str  # "user" or "surge"
    content: str
    created_at: datetime


class ChatRequest(BaseModel):
    session_id: str
    message: str
    model: Optional[str] = None  # Override model for this message


class LocalAction(BaseModel):
    """Instruction for the desktop client to execute locally on the user's machine."""
    action_type: str  # "exec", "read_file", "list_dir"
    command: Optional[str] = None
    path: Optional[str] = None


class ChatResponse(BaseModel):
    message: str
    terminal_session_id: Optional[str] = None
    command_result: Optional[ExecuteCommandResponse] = None
    terminal_snapshot: Optional[TerminalSnapshot] = None
    local_action: Optional[LocalAction] = None
    # Which peer produced the reply. "maestro" (default) or "surge-peer" when
    # a user addressed @surge directly. UI can bubble differently per source.
    source: Optional[str] = None
    # Day-7 disagreement UX. When set: Surge replied
    # but Maestro had a different read on the request. UI renders BOTH.
    # Shape: {"maestro_take": str, "summary": str}
    peer_disagreement: Optional[Dict[str, Any]] = None


class AdminUpdatePlanRequest(BaseModel):
    email: str
    plan: str
    paypal_subscription_id: Optional[str] = None


class AdminGrantRoleRequest(BaseModel):
    email: str
    role: str  # member | owner | platform_admin


class AdminCreateTenantRequest(BaseModel):
    name: str
    plan: Optional[str] = "free"  # free | team | business | enterprise


class AdminUpdateTenantRequest(BaseModel):
    name: Optional[str] = None
    plan: Optional[str] = None
    status: Optional[str] = None  # active | suspended | archived
    token_balance: Optional[int] = None  # operator override; rare


class AdminDeclareHostRequest(BaseModel):
    """Declare a fleet host (POST /v1/admin/fleet/hosts)."""
    hostname: str
    role: Optional[str] = "production-core"
    tags: Optional[list[str]] = None
    notes: Optional[str] = ""
    tenant_id: Optional[str] = None  # platform_admin can declare for any tenant; defaults to own


class AdminUpdateHostRequest(BaseModel):
    """Patch a fleet host (PATCH /v1/admin/fleet/hosts/{id})."""
    role: Optional[str] = None
    tags: Optional[list[str]] = None
    notes: Optional[str] = None
    lifecycle_status: Optional[str] = None  # declared | governed | archived


class AgentReportWitnessedRequest(BaseModel):
    """the fleet agent posts this for each discovery match (POST /v1/agent/witnessed)."""
    source_host_id: str
    target_hostname: str
    signal_type: str  # process | network | container | log
    pattern_id: str
    evidence: Optional[dict] = None
    confidence: Optional[str] = None  # override pattern default; low|medium|high


class AdminDismissFindingRequest(BaseModel):
    """Operator dismisses a witnessed finding as false-positive / out-of-scope."""
    reason: str


class AdminGovernFindingRequest(BaseModel):
    """Operator brings a witnessed finding under governance — creates a
    fleet_hosts row from it (POST /v1/admin/witnessed/{id}/declare-host)."""
    role: Optional[str] = "production-core"
    tags: Optional[list[str]] = None
    notes: Optional[str] = ""


class FlowRecord(BaseModel):
    """One east-west/north-south connection flow posted to
    POST /v1/discovery/ingest/flow. Field aliases accept the alternate names a
    NetFlow/Zeek/eBPF collector may emit (source/destination/port) so existing
    collectors keep working; `dst_port` is typed `int` so a non-numeric port is a
    clean 422 instead of a silently-accepted junk finding. `extra="allow"` keeps
    any collector-specific keys the analyzer ignores."""
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    src: Optional[str] = Field(default=None, validation_alias=AliasChoices("src", "source"))
    dst: Optional[str] = Field(default=None, validation_alias=AliasChoices("dst", "destination"))
    dst_port: Optional[int] = Field(default=None, validation_alias=AliasChoices("dst_port", "port"))
    proto: Optional[str] = None
    plane: Optional[str] = None  # advisory; the analyzer re-derives it


class DiscoveryFlowIngestRequest(BaseModel):
    """Body for POST /v1/discovery/ingest/flow: either a list of typed flows OR a
    raw sensor log (Zeek conn.log). Replaces the old untyped `payload: dict`, so
    wrong types (e.g. `flows` as a string, or a non-int `dst_port`) return 422
    rather than a 500 or a silent accept."""
    model_config = ConfigDict(extra="allow")
    tenant_id: str = "default"
    flows: Optional[list[FlowRecord]] = None
    raw_log: Optional[str] = None
    format: Optional[str] = None  # e.g. "zeek"
