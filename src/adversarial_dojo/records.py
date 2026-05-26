from __future__ import annotations

from typing import Any, Literal

import yaml
from pydantic import Field, ValidationError

from adversarial_dojo.common import StrictModel
from adversarial_dojo.tool_interfaces.models import split_qualified_tool_name


class ToolCallRecord(StrictModel):
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    result_content: str = ""
    structured_content: dict[str, Any] | None = None
    is_error: bool = False

    @property
    def server_name(self) -> str:
        return split_qualified_tool_name(self.tool)[0]

    @property
    def tool_name(self) -> str:
        return split_qualified_tool_name(self.tool)[1]


class LeakEvent(StrictModel):
    sink_id: str
    canary_id: str
    tool: str
    field: str
    destination_resource: str
    reason: str


class RuntimeEvent(StrictModel):
    event: str
    payload: dict[str, Any] = Field(default_factory=dict)


class AgentRunResult(StrictModel):
    final_text: str = ""
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    leak_events: list[LeakEvent] = Field(default_factory=list)
    resource_state: list[dict[str, Any]] = Field(default_factory=list)


class AttemptAnalysis(StrictModel):
    failure_stage: Literal[
        "scenario_invalid",
        "runtime_error",
        "victim_refused_immediately",
        "victim_gathered_context_then_refused",
        "victim_created_intermediate_artifact",
        "victim_attempted_sink_action",
        "attack_succeeded",
        "other",
    ]
    summary: str = Field(min_length=1)
    freeform_notes: str = ""
    refusal_reason_tags: list[str] = Field(default_factory=list)
    progress_signals: list[str] = Field(default_factory=list)
    red_team_recommendations: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


class AttemptRecord(StrictModel):
    attempt: int
    proposal: dict[str, Any] | None = None
    error: str | None = None
    victim_prompt: str | None = None
    victim_output: str = ""
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    leak_events: list[LeakEvent] = Field(default_factory=list)
    resource_state: list[dict[str, Any]] = Field(default_factory=list)
    analysis: AttemptAnalysis | None = None
    success: bool = False


class BenchmarkResult(StrictModel):
    scenario_id: str
    success: bool
    winning_attempt: int | None = None
    total_attempts: int
    attempts: list[AttemptRecord]
    output_dir: str | None = None


def parse_attempt_analysis(text: str) -> AttemptAnalysis:
    cleaned = _strip_code_fence(text)
    try:
        loaded = yaml.safe_load(cleaned)
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML/JSON attempt analysis: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ValueError("attempt analysis must be a mapping")
    try:
        return AttemptAnalysis.model_validate(loaded)
    except ValidationError as exc:
        raise ValueError(str(exc)) from exc


def _strip_code_fence(text: str) -> str:
    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped
    lines = stripped.splitlines()
    if len(lines) >= 2 and lines[-1].strip() == "```":
        return "\n".join(lines[1:-1]).strip()
    return stripped
