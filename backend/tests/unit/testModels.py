from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from apkscan.models import (
    ApkInfo,
    Component,
    ComponentType,
    Features,
    Finding,
    FindingSource,
    Report,
    Risk,
    RiskLevel,
    Severity,
)


def test_features_default_empty():
    features = Features()

    assert features.groups == {}
    assert features.components == []
    assert features.flags == {}


def test_features_instances_do_not_share_collections():
    first = Features()
    second = Features()

    first.groups["permissions"] = {"android.permission.INTERNET"}

    assert second.groups == {}


def test_component_json_roundtrip():
    component = Component(
        type=ComponentType.RECEIVER,
        name="com.example.BootReceiver",
        exported=True,
        intent_actions=["android.intent.action.BOOT_COMPLETED"],
    )
    features = Features(components=[component])

    restored = Features.model_validate_json(features.model_dump_json())

    assert restored.components[0] == component


def test_severity_from_string():
    assert Severity("critical") is Severity.CRITICAL


def test_finding_rejects_unknown_source():
    with pytest.raises(ValidationError):
        Finding(
            rule_id="X",
            source="manual",
            severity=Severity.LOW,
            category="test",
        )


def test_risk_score_out_of_range():
    with pytest.raises(ValidationError):
        Risk(score=120, level=RiskLevel.HIGH)


def test_report_serializes_to_json():
    report = Report(
        tool_version="0.1.0",
        analyzed_at=datetime.now(UTC),
        apk=ApkInfo(file_name="app.apk", size_bytes=1, md5="x", sha1="y", sha256="z"),
        risk=Risk(score=42.0, level=RiskLevel.MEDIUM),
        findings=[
            Finding(
                rule_id="SMS_INTERCEPT",
                source=FindingSource.BEHAVIOR,
                severity=Severity.CRITICAL,
                category="fraud",
            )
        ],
    )

    data = report.model_dump(mode="json")

    assert data["risk"]["level"] == "medium"
    assert data["findings"][0]["source"] == "behavior"
    assert data["ml_prediction"] is None
