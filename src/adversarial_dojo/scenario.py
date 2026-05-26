from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import Field, ValidationError, model_validator

from adversarial_dojo.common import StrictModel
from adversarial_dojo.config import ScenarioAgents
from adversarial_dojo.tool_interfaces.models import ToolInterface


class TaskSpec(StrictModel):
    user_task: str = Field(min_length=1)
    red_team_task: str = Field(min_length=1)


class UserTaskProposal(StrictModel):
    user_task: str = Field(min_length=1)


Principal = Literal["victim", "attacker", "public"]


class AccessPolicy(StrictModel):
    readers: list[Principal] = Field(default_factory=list)
    writers: list[Principal] = Field(default_factory=list)


class ResourceSpec(StrictModel):
    id: str = Field(min_length=1, pattern=r"^[A-Za-z0-9_-]+$")
    kind: str = Field(min_length=1)
    content: Any = ""
    identifiers: dict[str, Any] = Field(default_factory=dict)
    access: AccessPolicy


class CanarySpec(StrictModel):
    id: str = Field(min_length=1, pattern=r"^[A-Za-z0-9_-]+$")
    resource_id: str = Field(min_length=1)
    value: str = Field(min_length=1)

    @property
    def placeholder(self) -> str:
        return canary_placeholder(self.id)


class SinkSpec(StrictModel):
    id: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    match: dict[str, Any] = Field(default_factory=dict)
    payload_fields: list[str] = Field(min_length=1)
    destination_resource: str = Field(min_length=1)


class ToolImplSpec(StrictModel):
    tool: str = Field(min_length=1)
    body: str = Field(min_length=1)


class ScenarioProposal(StrictModel):
    red_team_task: str = Field(min_length=1)
    resources: list[ResourceSpec] = Field(default_factory=list)
    canaries: list[CanarySpec] = Field(default_factory=list)
    sinks: list[SinkSpec] = Field(default_factory=list)
    tool_impls: list[ToolImplSpec] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def reject_execution_owned_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            forbidden = sorted(
                set(data)
                & {
                    "agents",
                    "environment",
                    "evaluators",
                    "exfiltration_sinks",
                    "id",
                    "seed",
                    "secrets",
                    "task",
                    "tool_interface",
                    "tool_surface",
                    "user_task",
                }
            )
            if forbidden:
                raise ValueError(
                    "scenario proposal must not include execution-owned, user-task-owned, or legacy fields: "
                    + ", ".join(forbidden)
                )
        return data

    @model_validator(mode="after")
    def validate_internal_references(self) -> ScenarioProposal:
        _reject_duplicate_ids("resource", [resource.id for resource in self.resources])
        _reject_duplicate_ids("canary", [canary.id for canary in self.canaries])
        _reject_duplicate_ids("canary value", [canary.value for canary in self.canaries])
        _reject_duplicate_ids("sink", [sink.id for sink in self.sinks])
        _reject_duplicate_ids("tool impl", [impl.tool for impl in self.tool_impls])

        resources = {resource.id: resource for resource in self.resources}
        for canary in self.canaries:
            resource = resources.get(canary.resource_id)
            if resource is None:
                raise ValueError(
                    f"canary {canary.id} references unknown resource: {canary.resource_id}"
                )
            if canary.placeholder not in _stringify_resource_content(resource.content):
                raise ValueError(
                    f"canary placeholder {canary.placeholder} must appear in source resource {resource.id}"
                )
            if _resource_readable_by_attacker_or_public(resource):
                raise ValueError(
                    f"canary source resource {resource.id} is readable by attacker or public"
                )

        for sink in self.sinks:
            destination = resources.get(sink.destination_resource)
            if destination is None:
                raise ValueError(
                    f"sink {sink.id} references unknown destination resource: {sink.destination_resource}"
                )
            if not _resource_readable_by_attacker_or_public(destination):
                raise ValueError(
                    f"sink destination resource {destination.id} must be readable by attacker or public"
                )
        return self


class Scenario(StrictModel):
    id: str = Field(min_length=1)
    agents: ScenarioAgents
    task: TaskSpec
    resources: list[ResourceSpec] = Field(default_factory=list)
    canaries: list[CanarySpec] = Field(default_factory=list)
    sinks: list[SinkSpec] = Field(default_factory=list)
    tool_interface: ToolInterface
    tool_impls: list[ToolImplSpec] = Field(default_factory=list)
    max_tool_result_chars: int = Field(default=4000, ge=1)
    tool_timeout_seconds: float = Field(default=2.0, gt=0)

    @model_validator(mode="after")
    def validate_tool_references(self) -> Scenario:
        known_tools = self.tool_interface.qualified_tool_names
        for sink in self.sinks:
            if sink.tool not in known_tools:
                raise ValueError(f"sink {sink.id} references unknown tool: {sink.tool}")
        for impl in self.tool_impls:
            if impl.tool not in known_tools:
                raise ValueError(f"tool impl references unknown tool: {impl.tool}")
        return self

    @classmethod
    def from_yaml_file(cls, path: str | Path) -> Scenario:
        with Path(path).open("r", encoding="utf-8") as handle:
            return cls.model_validate(yaml.safe_load(handle))

    def to_yaml(self) -> str:
        return yaml.safe_dump(self.model_dump(mode="json"), sort_keys=False)


class ToolResult(StrictModel):
    content: str = ""
    structured_content: dict[str, Any] | None = None
    is_error: bool = False


def parse_scenario_proposal(text: str) -> ScenarioProposal:
    cleaned = _strip_code_fence(text)
    try:
        loaded = yaml.safe_load(cleaned)
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML/JSON scenario proposal: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ValueError("scenario proposal must be a mapping")
    try:
        return ScenarioProposal.model_validate(loaded)
    except ValidationError as exc:
        raise ValueError(str(exc)) from exc


def parse_user_task_proposal(text: str) -> UserTaskProposal:
    cleaned = _strip_code_fence(text)
    try:
        loaded = yaml.safe_load(cleaned)
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML/JSON user task proposal: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ValueError("user task proposal must be a mapping")
    try:
        return UserTaskProposal.model_validate(loaded)
    except ValidationError as exc:
        raise ValueError(str(exc)) from exc


def canary_placeholder(canary_id: str) -> str:
    return f"{{{{canary.{canary_id}}}}}"


def find_canary_placeholders(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, str):
        found.update(_CANARY_PLACEHOLDER_RE.findall(value))
    elif isinstance(value, list):
        for item in value:
            found.update(find_canary_placeholders(item))
    elif isinstance(value, dict):
        for item in value.values():
            found.update(find_canary_placeholders(item))
    return found


def dict_contains(actual: dict[str, Any], expected_subset: dict[str, Any]) -> bool:
    for key, expected_value in expected_subset.items():
        if key not in actual:
            return False
        actual_value = actual[key]
        if isinstance(expected_value, dict):
            if not isinstance(actual_value, dict) or not dict_contains(
                actual_value, expected_value
            ):
                return False
        elif actual_value != expected_value:
            return False
    return True


def get_path(data: dict[str, Any], path: str) -> Any:
    value: Any = data
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _strip_code_fence(text: str) -> str:
    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped
    lines = stripped.splitlines()
    if len(lines) >= 2 and lines[-1].strip() == "```":
        return "\n".join(lines[1:-1]).strip()
    return stripped


def _reject_duplicate_ids(label: str, values: list[str]) -> None:
    duplicates = sorted({value for value in values if values.count(value) > 1})
    if duplicates:
        raise ValueError(f"duplicate {label} ids: {', '.join(duplicates)}")


def _resource_readable_by_attacker_or_public(resource: ResourceSpec) -> bool:
    return bool({"attacker", "public"} & set(resource.access.readers))


def _stringify_resource_content(content: Any) -> str:
    return yaml.safe_dump(content, sort_keys=True)


_CANARY_PLACEHOLDER_RE = re.compile(r"\{\{canary\.([A-Za-z0-9_-]+)\}\}")
