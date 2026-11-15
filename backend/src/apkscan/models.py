from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

FlagValue = str | int | float | bool | None

class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

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


class Component(StrictModel):
    type: ComponentType
    name: str
    exported: bool
    intentActions: list[str] = Field(default_factory = list)
    requiredPermission: str | None = None


class Features(StrictModel):
    groups: dict[str, set[str]] = Field(default_factory = dict)
    components: list[Component] = Field(default_factory = list)
    flags: dict[str, FlagValue] = Field(default_factory = dict)


class Finding(StrictModel):
    ruleId: str
    source: FindingSource
    severity: Severity
    category: str
    evidence: list[str] = Field(default_factory = list)


class FeatureContribution(StrictModel):
    feature: str
    weight: float


class MlPrediction(StrictModel):
    probability: float = Field(ge = 0.0, le = 1.0)
    topFeatures: list[FeatureContribution] = Field(default_factory = list)


class Risk(StrictModel):
    score: float = Field(ge = 0.0, le = 100.0)
    level: RiskLevel


class ApkInfo(StrictModel):
    fileName: str
    sizeBytes: int
    md5: str
    sha1: str
    sha256: str
    package: str | None = None
    appName: str | None = None
    versionName: str | None = None
    versionCode: str | None = None
    minSdk: int | None = None
    targetSdk: int | None = None


class Report(StrictModel):
    toolVersion: str
    analyzedAt: datetime
    apk: ApkInfo
    risk: Risk
    findings: list[Finding] = Field(default_factory = list)
    mlPrediction: MlPrediction | None = None
    features: Features = Field(default_factory = Features)

class ComponentCondition(StrictModel):
    type: ComponentType | None = None
    exported: bool | None = None
    action: str | None = None


class RuleCondition(StrictModel):
    permission: str | None = None
    intentAction: str | None = None
    flag: str | None = None
    component: ComponentCondition | None = None


class Rule(StrictModel):
    id: str
    name: str
    category: str
    severity: Severity
    mitre: list[str] = Field(default_factory = list)
    description: str
    allOf: list[RuleCondition] = Field(default_factory = list)
    anyOf: list[RuleCondition] = Field(default_factory = list)
