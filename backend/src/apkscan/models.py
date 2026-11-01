# Datové modely, které si předávají jednotlivé moduly a ze kterých vzniká JSON report.

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field

# Hodnota jednoho příznaku, např. debuggable=True nebo target_sdk=33.
FlagValue = str | int | float | bool | None


# Závažnost nálezu, podle které se určí jeho váha v risk score.
class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Výsledná úroveň rizika, do které se převede číselné skóre.
class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Typ komponenty tak, jak je deklarovaná v AndroidManifest.xml.
class ComponentType(StrEnum):
    ACTIVITY = "activity"
    SERVICE = "service"
    RECEIVER = "receiver"
    PROVIDER = "provider"


# Odkud nález pochází: z behaviorálního pravidla v YAML, nebo ze signatury YARA.
class FindingSource(StrEnum):
    BEHAVIOR = "behavior"
    YARA = "yara"


# Komponenta z manifestu, u které se sleduje export, intent akce a oprávnění volajícího.
class Component(BaseModel):
    type: ComponentType
    name: str
    exported: bool
    intent_actions: list[str] = Field(default_factory=list)
    required_permission: str | None = None


# Rysy extrahované z APK, se kterými pracují detekční pravidla i ML model.
class Features(BaseModel):
    groups: dict[str, set[str]] = Field(default_factory=dict)
    components: list[Component] = Field(default_factory=list)
    flags: dict[str, FlagValue] = Field(default_factory=dict)


# Nález pravidla spolu s konkrétními hodnotami, které ho splnily.
class Finding(BaseModel):
    rule_id: str
    source: FindingSource
    severity: Severity
    category: str
    evidence: list[str] = Field(default_factory=list)


# Rys, který ovlivnil predikci ML modelu, a jak moc ji ovlivnil.
class FeatureContribution(BaseModel):
    feature: str
    weight: float


# Pravděpodobnost malwaru podle ML modelu a rysy, které ji nejvíc ovlivnily.
class MlPrediction(BaseModel):
    probability: float = Field(ge=0.0, le=1.0)
    top_features: list[FeatureContribution] = Field(default_factory=list)


# Risk score v rozsahu 0–100 a úroveň rizika, která z něj vyplývá.
class Risk(BaseModel):
    score: float = Field(ge=0.0, le=100.0)
    level: RiskLevel


# Hashe a velikost souboru spolu se základními údaji o aplikaci z manifestu.
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


# Výsledek analýzy jednoho APK, který se ukládá jako JSON a HTML.
class Report(BaseModel):
    tool_version: str
    analyzed_at: datetime
    apk: ApkInfo
    risk: Risk
    findings: list[Finding] = Field(default_factory=list)
    ml_prediction: MlPrediction | None = None
    features: Features = Field(default_factory=Features)
