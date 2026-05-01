from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any

from adversarial_dojo.models import AttackScenario, MockEnvironment


@dataclass(frozen=True)
class RuntimeSecrets:
    values: dict[str, str]

    def redacted(self) -> dict[str, str]:
        return {secret_id: "<redacted>" for secret_id in self.values}


def materialize_runtime_secrets(scenario: AttackScenario) -> tuple[AttackScenario, RuntimeSecrets]:
    if not scenario.secrets:
        return scenario, RuntimeSecrets(values={})
    values = {secret.id: _secret_value(secret.id, secret.token) for secret in scenario.secrets}
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


def _secret_value(secret_id: str, token: str) -> str:
    default_token = f"{{{{secret.{secret_id}}}}}"
    if token != default_token:
        return token
    return f"ADOJO_SECRET_{secret_id}_{secrets.token_hex(12)}"
