from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field

FlagValue = str | int | float | bool | None


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ComponentType(StrEnum):
    ACTIVITY = "activity"
    SERVICE = "service"
    RECEIVER = "receiver"
    PROVIDER = "provider"


class FindingSource(StrEnum):
    BEHAVIOR = "behavior"
    YARA = "yara"


class Component(BaseModel):
    type: ComponentType
    name: str
    exported: bool
    intent_actions: list[str] = Field(default_factory=list)
    required_permission: str | None = None


class Features(BaseModel):
    groups: dict[str, set[str]] = Field(default_factory=dict)
    components: list[Component] = Field(default_factory=list)
    flags: dict[str, FlagValue] = Field(default_factory=dict)


class Finding(BaseModel):
    rule_id: str
    source: FindingSource
    severity: Severity
    category: str
    evidence: list[str] = Field(default_factory=list)


class FeatureContribution(BaseModel):
    feature: str
    weight: float


class MlPrediction(BaseModel):
    probability: float = Field(ge=0.0, le=1.0)
    top_features: list[FeatureContribution] = Field(default_factory=list)


class Risk(BaseModel):
    score: float = Field(ge=0.0, le=100.0)
    level: RiskLevel


class ApkInfo(BaseModel):
    file_name: str
    size_bytes: int
    md5: str
    sha1: str
    sha256: str
    package: str | None = None
    app_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None


class Report(BaseModel):
    tool_version: str
    analyzed_at: datetime
    apk: ApkInfo
    risk: Risk
    findings: list[Finding] = Field(default_factory=list)
    ml_prediction: MlPrediction | None = None
    features: Features = Field(default_factory=Features)
