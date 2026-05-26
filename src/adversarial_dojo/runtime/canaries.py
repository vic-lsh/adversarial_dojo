from __future__ import annotations

import json
from typing import Any

from adversarial_dojo.scenario import (
    CanarySpec,
    canary_placeholder,
    find_canary_placeholders,
)


class CanaryRegistry:
    def __init__(self, canaries: list[CanarySpec]) -> None:
        self._canaries = {canary.id: canary for canary in canaries}
        self._value_to_id = {canary.value: canary.id for canary in canaries}
        self.observed: set[str] = set()

    def placeholder(self, canary_id: str) -> str:
        return canary_placeholder(canary_id)

    def value(self, canary_id: str) -> str:
        return self._canaries[canary_id].value

    def known_ids(self) -> set[str]:
        return set(self._canaries)

    def placeholders_in(self, value: Any) -> set[str]:
        return find_canary_placeholders(value)

    def values_in(self, value: Any) -> set[str]:
        text = _stringify(value)
        return {
            canary_id
            for canary_value, canary_id in self._value_to_id.items()
            if canary_value in text
        }

    def substitute(self, value: Any) -> Any:
        if isinstance(value, str):
            rendered = value
            for canary in self._canaries.values():
                rendered = rendered.replace(canary.placeholder, canary.value)
            return rendered
        if isinstance(value, list):
            return [self.substitute(item) for item in value]
        if isinstance(value, dict):
            return {key: self.substitute(item) for key, item in value.items()}
        return value

    def remask(self, value: Any) -> Any:
        if isinstance(value, str):
            remasked = value
            for canary in sorted(
                self._canaries.values(), key=lambda item: len(item.value), reverse=True
            ):
                remasked = remasked.replace(canary.value, canary.placeholder)
            return remasked
        if isinstance(value, list):
            return [self.remask(item) for item in value]
        if isinstance(value, dict):
            return {key: self.remask(item) for key, item in value.items()}
        return value

    def mark_observed_from_response(self, value: Any) -> set[str]:
        observed_now = self.values_in(value)
        self.observed.update(observed_now)
        return observed_now


def _stringify(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except TypeError:
        return str(value)
