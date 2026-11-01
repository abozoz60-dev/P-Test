"""Pydantic request/response schemas."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.db.models import Role, ScanStatus, Severity, ValidationStatus


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: Role


class UserCreate(BaseModel):
    username: str
    password: str
    role: Role = Role.viewer


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    role: Role
    is_active: bool


class TargetCreate(BaseModel):
    name: str
    scope: str  # comma-separated IPs/CIDRs/hostnames
    owner_attestation: str = ""
    authorization_ref: str = ""


class TargetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    scope: str
    owner_attestation: str
    authorization_ref: str
    approved: bool
    approved_by: str
    enabled: bool
    created_by: str
    created_at: datetime


class ScanCreate(BaseModel):
    target_id: int
    modules: list[str]


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    target_id: int
    modules: str
    status: ScanStatus
    operator: str
    started_at: datetime
    finished_at: datetime | None
    error: str


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    scan_id: int
    vuln_id: str
    asset: str
    service: str
    category: str
    severity: Severity
    confidence: str
    title: str
    evidence: str
    reproduction: str
    impact: str
    remediation: str
    references: str
    status: ValidationStatus
    created_at: datetime


class FindingStatusUpdate(BaseModel):
    status: ValidationStatus


class CheckOut(BaseModel):
    id: str
    name: str
    category: str
    description: str
    safe: bool
