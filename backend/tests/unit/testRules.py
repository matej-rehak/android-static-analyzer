from pathlib import Path

import pytest

from apkscan.exceptions import InvalidRuleError
from apkscan.models import ComponentType, Severity
from apkscan.rules import loadRules

VALID_RULE = """
rules:
  - id: SMS_INTERCEPT
    name: Zachytávání příchozích SMS
    category: fraud
    severity: critical
    mitre: [T1582]
    description: Testovací pravidlo.
    allOf:
      - permission: android.permission.RECEIVE_SMS
      - component:
          type: receiver
          exported: true
          action: android.provider.Telephony.SMS_RECEIVED
"""


def writeRulesFile(directory: Path, fileName: str, content: str) -> None:
    filePath = directory / fileName
    filePath.write_text(content, encoding="utf-8")


def testValidRuleIsLoaded(tmp_path: Path):
    writeRulesFile(tmp_path, "fraud.yaml", VALID_RULE)

    rules = loadRules(tmp_path)

    assert len(rules) == 1
    assert rules[0].id == "SMS_INTERCEPT"
    assert rules[0].severity == Severity.CRITICAL
    assert rules[0].allOf[1].component is not None
    assert rules[0].allOf[1].component.type == ComponentType.RECEIVER


def testDuplicateRuleIdIsRejected(tmp_path: Path):
    writeRulesFile(tmp_path, "first.yaml", VALID_RULE)
    writeRulesFile(tmp_path, "second.yaml", VALID_RULE)

    with pytest.raises(InvalidRuleError, match="definované vícekrát"):
        loadRules(tmp_path)


def testConditionWithTwoTypesIsRejected(tmp_path: Path):
    content = """
rules:
  - id: BROKEN
    name: Rozbité pravidlo
    category: test
    severity: low
    description: Podmínka má dva typy.
    allOf:
      - permission: android.permission.INTERNET
        flag: debuggable
"""
    writeRulesFile(tmp_path, "broken.yaml", content)

    with pytest.raises(InvalidRuleError, match="právě jeden typ"):
        loadRules(tmp_path)


def testUnknownSeverityIsRejected(tmp_path: Path):
    content = VALID_RULE.replace("severity: critical", "severity: extreme")
    writeRulesFile(tmp_path, "fraud.yaml", content)

    with pytest.raises(InvalidRuleError):
        loadRules(tmp_path)


def testTypoInConditionIsRejected(tmp_path: Path):
    content = VALID_RULE.replace(
        "- permission:",
        "- permision:"
    )
    writeRulesFile(tmp_path, "fraud.yaml", content)

    with pytest.raises(InvalidRuleError):
        loadRules(tmp_path)


def testFileWithoutRulesListIsRejected(tmp_path: Path):
    writeRulesFile(tmp_path, "empty.yaml", "nic: tady\n")

    with pytest.raises(InvalidRuleError):
        loadRules(tmp_path)
