from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml

from adversarial_dojo.mcp_harness import MockMcpHarness
from adversarial_dojo.models import (
    AttackPatch,
    AttackScenarioProposal,
    AttemptAnalysis,
    MockEnvironment,
    MockMcpServer,
    MockTool,
    ToolCallRecord,
)

SUBMISSION_SERVER_NAME = "adversarial_dojo_submission"
SUBMIT_SCENARIO_TOOL = "submit_attack_scenario"
SUBMIT_PATCH_TOOL = "submit_attack_patch"
SUBMIT_ANALYSIS_TOOL = "submit_attempt_analysis"

SubmissionKind = Literal["scenario", "patch", "analysis"]


class RedTeamSubmissionHarness:
    def __init__(self, kind: SubmissionKind, output_dir: Path | None, attempt: int) -> None:
        self.kind = kind
        self.output_dir = output_dir
        self.attempt = attempt
        self._harness = MockMcpHarness(_submission_environment(kind), output_dir=output_dir, attempt=attempt)
        self.mcp_servers = []

    def __enter__(self) -> RedTeamSubmissionHarness:
        self._harness.__enter__()
        self.mcp_servers = self._harness.mcp_servers
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._harness.__exit__(exc_type, exc, tb)

    def collect_submission(self, extra_calls: list[ToolCallRecord] | None = None) -> dict[str, Any] | None:
        return extract_submission(self._harness.collect_calls() + list(extra_calls or []), self.kind)


def extract_submission(calls: list[ToolCallRecord], kind: SubmissionKind) -> dict[str, Any] | None:
    tool_name = _tool_name(kind)
    for call in reversed(calls):
        if call.server_name != SUBMISSION_SERVER_NAME:
            continue
        if call.tool_name != tool_name:
            continue
        return call.arguments
    return None


def submission_to_text(submission: dict[str, Any]) -> str:
    return yaml.safe_dump(submission, sort_keys=False)


def submission_tool_name(kind: SubmissionKind) -> str:
    return f"{SUBMISSION_SERVER_NAME}.{_tool_name(kind)}"


def _submission_environment(kind: SubmissionKind) -> MockEnvironment:
    tool_name = _tool_name(kind)
    if kind == "scenario":
        model = AttackScenarioProposal
        description = "Submit the complete AttackScenarioProposal object. This is the only accepted way to return a candidate scenario proposal."
    elif kind == "patch":
        model = AttackPatch
        description = "Submit the complete AttackPatch object. This is the only accepted way to return a patch proposal."
    else:
        model = AttemptAnalysis
        description = "Submit the complete AttemptAnalysis object. This is the only accepted way to return structured post-attempt analysis."
    return MockEnvironment(
        mcp_servers=[
            MockMcpServer(
                name=SUBMISSION_SERVER_NAME,
                tools=[
                    MockTool(
                        name=tool_name,
                        description=description,
                        args_schema=model.model_json_schema(),
                        responses=[{"content": "submission accepted"}],
                    )
                ],
            )
        ]
    )


def _tool_name(kind: SubmissionKind) -> str:
    if kind == "scenario":
        return SUBMIT_SCENARIO_TOOL
    if kind == "patch":
        return SUBMIT_PATCH_TOOL
    return SUBMIT_ANALYSIS_TOOL
