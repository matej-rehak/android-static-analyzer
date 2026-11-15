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


def testFeaturesDefaultEmpty():
    features = Features()

    assert features.groups == {}
    assert features.components == []
    assert features.flags == {}


def testFeaturesInstancesDoNotShareCollections():
    first = Features()
    second = Features()

    first.groups["permissions"] = {"android.permission.INTERNET"}

    assert second.groups == {}


def testComponentJsonRoundtrip():
    component = Component(
        type = ComponentType.RECEIVER,
        name = "com.example.BootReceiver",
        exported = True,
        intentActions = ["android.intent.action.BOOT_COMPLETED"]
    )
    features = Features(
        components = [component]
    )

    restored = Features.model_validate_json(features.model_dump_json())

    assert restored.components[0] == component
    assert restored.components[0].intentActions == ["android.intent.action.BOOT_COMPLETED"]


def testSeverityFromString():
    assert Severity("critical") is Severity.CRITICAL


def testFindingRejectsUnknownSource():
    with pytest.raises(ValidationError):
        Finding(
            ruleId = "X",
            source = "manual",
            severity = Severity.LOW,
            category = "test"
        )


def testUnknownFieldIsRejected():
    with pytest.raises(ValidationError):
        Risk(
            score = 10.0,
            level = RiskLevel.LOW,
            rule_id = "X"
        )


def testRiskScoreOutOfRange():
    with pytest.raises(ValidationError):
        Risk(
            score = 120,
            level = RiskLevel.HIGH
        )


def testReportSerializesToJson():
    report = Report(
        toolVersion = "0.1.0",
        analyzedAt = datetime.now(UTC),
        apk = ApkInfo(
            fileName = "app.apk",
            sizeBytes = 1,
            md5 = "x",
            sha1 = "y",
            sha256 = "z"
        ),
        risk = Risk(
            score = 42.0,
            level = RiskLevel.MEDIUM
        ),
        findings = [
            Finding(
                ruleId = "SMS_INTERCEPT",
                source = FindingSource.BEHAVIOR,
                severity = Severity.CRITICAL,
                category = "fraud"
            )
        ]
    )

    data = report.model_dump(mode = "json")

    assert data["risk"]["level"] == "medium"
    assert data["findings"][0]["source"] == "behavior"
    assert data["mlPrediction"] is None
