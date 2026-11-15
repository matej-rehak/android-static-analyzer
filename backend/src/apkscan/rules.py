
from pathlib import Path

import yaml
from pydantic import ValidationError

from apkscan.exceptions import InvalidRuleError
from apkscan.models import Rule, RuleCondition


def validateCondition(condition: RuleCondition, ruleId: str) -> None:
    conditionTypes = [
        condition.permission,
        condition.intentAction,
        condition.flag,
        condition.component
    ]

    numberOfTypes = sum(
        value is not None for value in conditionTypes
    )

    if numberOfTypes != 1:
        raise InvalidRuleError("Podmínka v pravidle " + ruleId + " musí mít právě jeden typ")


def validateRule(rule: Rule) -> None:
    if not rule.allOf and not rule.anyOf:
        raise InvalidRuleError("Pravidlo " + rule.id + " nemá žádnou podmínku")

    for condition in rule.allOf:
        validateCondition(condition, rule.id)

    for condition in rule.anyOf:
        validateCondition(condition, rule.id)


def loadRules(rulesDirectory: Path) -> list[Rule]:
    rules = []
    seenIds = set()

    for rulesFile in sorted(rulesDirectory.glob("*.yaml")):
        try:
            content = yaml.safe_load(
                rulesFile.read_text(encoding="utf-8")
            )
        except yaml.YAMLError as error:
            message = ("Neplatný YAML soubor " + str(rulesFile) + ": " + str(error))
            raise InvalidRuleError(message) from error

        if not isinstance(content, dict) or "rules" not in content:
            raise InvalidRuleError("Soubor " + str(rulesFile) + " neobsahuje seznam rules")

        if not isinstance(content["rules"], list):
            raise InvalidRuleError("Soubor " + str(rulesFile) + " neobsahuje platný seznam rules")

        for ruleData in content["rules"]:
            try:
                rule = Rule.model_validate(ruleData)
            except ValidationError as error:
                message = ("Neplatné pravidlo v souboru " + str(rulesFile) + ": " + str(error))
                raise InvalidRuleError(message) from error

            if rule.id in seenIds:
                raise InvalidRuleError("Pravidlo " + rule.id + " je definované vícekrát")

            validateRule(rule)

            seenIds.add(rule.id)
            rules.append(rule)

    return rules
