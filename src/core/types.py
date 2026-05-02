from __future__ import annotations

from typing import Literal, Optional
from pydantic import BaseModel


class FraudReport(BaseModel):
    riskScore: int
    riskLevel: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    indicators: list[str]
    domainAge: Optional[str] = None
    domainCountry: Optional[str] = None
    cmfRegistered: Optional[bool] = None
    explanation: str
    recommendations: list[str]


class WhoisData(BaseModel):
    domain: str
    registrar: Optional[str] = None
    created: Optional[str] = None
    expires: Optional[str] = None
    country: Optional[str] = None
    status: Optional[str] = None
    nameservers: Optional[list[str]] = None


class CmfEntityResult(BaseModel):
    found: bool
    entityName: Optional[str] = None
    entityType: Optional[str] = None
    matchScore: Optional[float] = None


class PatternCheckResult(BaseModel):
    patterns: list[str]
    suspiciousCount: int
    details: list[str]
