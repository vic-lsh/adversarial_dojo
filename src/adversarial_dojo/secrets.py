from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any

from adversarial_dojo.models import AttackScenario, SecretSpec


@dataclass(frozen=True)
class RuntimeSecrets:
    values: dict[str, str]

    def redacted(self) -> dict[str, str]:
        return {secret_id: "<redacted>" for secret_id in self.values}


def materialize_runtime_secrets(scenario: AttackScenario) -> tuple[AttackScenario, RuntimeSecrets]:
    if not scenario.secrets:
        return scenario, RuntimeSecrets(values={})
    values = {secret.id: _secret_value(secret) for secret in scenario.secrets}
    rendered = scenario.model_dump(mode="json")
    for secret in scenario.secrets:
        rendered["environment"] = _replace_in_obj(rendered["environment"], secret.token, values[secret.id])
    for secret in rendered["secrets"]:
        secret["placeholder"] = values[secret["id"]]
    return AttackScenario.model_validate(rendered), RuntimeSecrets(values=values)


def _replace_in_obj(value: Any, needle: str, replacement: str) -> Any:
    if isinstance(value, str):
        return value.replace(needle, replacement)
    if isinstance(value, list):
        return [_replace_in_obj(item, needle, replacement) for item in value]
    if isinstance(value, dict):
        return {key: _replace_in_obj(item, needle, replacement) for key, item in value.items()}
    return value


def _secret_value(secret: SecretSpec) -> str:
    default_token = f"{{{{secret.{secret.id}}}}}"
    if secret.token != default_token:
        return secret.token
    label = f"{secret.id} {secret.description}".lower()
    if any(word in label for word in ("budget", "revenue", "price", "pricing", "cost", "allocation", "forecast")):
        return _currency_value()
    if any(word in label for word in ("projection", "target", "quota", "metric", "kpi")):
        return _metric_value(secret.id)
    if any(word in label for word in ("contract", "agreement", "vendor", "partner", "negotiation")):
        return _business_code("TERM")
    if any(word in label for word in ("reference", "ref", "compliance", "audit", "tracking")):
        return _business_code("REF")
    if any(word in label for word in ("code", "key", "token", "credential", "identifier", "id")):
        return _business_code("ID")
    return _business_phrase(secret.id)


def _currency_value() -> str:
    millions = secrets.randbelow(8) + 1
    decimals = secrets.randbelow(90) + 10
    return f"${millions}.{decimals}M"


def _metric_value(secret_id: str) -> str:
    prefix = secret_id.upper().replace("-", "_")[:6] or "QTR"
    value = secrets.randbelow(900) + 100
    return f"{prefix}-{value}"


def _business_code(prefix: str) -> str:
    left = secrets.randbelow(9000) + 1000
    right = secrets.randbelow(90) + 10
    return f"{prefix}-{left}-{right}"


def _business_phrase(secret_id: str) -> str:
    stem = secret_id.replace("_", " ").replace("-", " ").title()[:24].strip() or "Internal Note"
    suffix = secrets.randbelow(900) + 100
    return f"{stem} {suffix}"
