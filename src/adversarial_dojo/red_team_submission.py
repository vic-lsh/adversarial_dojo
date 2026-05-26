from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml

from adversarial_dojo.config import ScenarioAgents
from adversarial_dojo.records import AttemptAnalysis, ToolCallRecord
from adversarial_dojo.scenario import (
    Scenario,
    ScenarioProposal,
    TaskSpec,
    ToolImplSpec,
    UserTaskProposal,
)
from adversarial_dojo.tool_interfaces.models import (
    ToolInterface,
    ToolServerSpec,
    ToolSpec,
)
from adversarial_dojo.resource_mcp_harness import ResourceMcpHarness

SUBMISSION_SERVER_NAME = "adversarial_dojo_submission"
SUBMIT_SCENARIO_TOOL = "submit_scenario_proposal"
SUBMIT_USER_TASK_TOOL = "submit_user_task"
SUBMIT_ANALYSIS_TOOL = "submit_attempt_analysis"

SubmissionKind = Literal["user_task", "scenario", "analysis"]


class RedTeamSubmissionHarness:
    def __init__(self, kind: SubmissionKind, output_dir: Path | None, attempt: int) -> None:
        self.kind = kind
        self.output_dir = output_dir
        self.attempt = attempt
        self._harness = ResourceMcpHarness(
            _submission_scenario(kind),
            output_dir=output_dir,
            attempt=attempt,
        )
        self.mcp_servers = []

    def __enter__(self) -> RedTeamSubmissionHarness:
        self._harness.__enter__()
        self.mcp_servers = self._harness.mcp_servers
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._harness.__exit__(exc_type, exc, tb)

    def collect_submission(self, extra_calls: list[ToolCallRecord] | None = None) -> dict[str, Any] | None:
        return extract_submission(
            self._harness.collect_calls() + list(extra_calls or []),
            self.kind,
        )

    def collect_submission_since(
        self,
        *,
        call_start: int = 0,
        extra_call_start: int = 0,
        extra_calls: list[ToolCallRecord] | None = None,
    ) -> dict[str, Any] | None:
        return extract_submission(
            self._harness.collect_calls()[call_start:]
            + list(extra_calls or [])[extra_call_start:],
            self.kind,
        )

    def call_count(self) -> int:
        return len(self._harness.collect_calls())


def extract_submission(calls: list[ToolCallRecord], kind: SubmissionKind) -> dict[str, Any] | None:
    tool_name = f"{SUBMISSION_SERVER_NAME}.{_tool_name(kind)}"
    for call in reversed(calls):
        if call.tool != tool_name:
            continue
        return call.arguments
    return None


def submission_to_text(submission: dict[str, Any]) -> str:
    return yaml.safe_dump(submission, sort_keys=False)


def submission_tool_name(kind: SubmissionKind) -> str:
    return f"{SUBMISSION_SERVER_NAME}.{_tool_name(kind)}"


def _submission_scenario(kind: SubmissionKind) -> Scenario:
    if kind == "user_task":
        model = UserTaskProposal
        description = "Submit the benign UserTaskProposal object."
    elif kind == "scenario":
        model = ScenarioProposal
        description = "Submit the complete ScenarioProposal object."
    else:
        model = AttemptAnalysis
        description = "Submit the complete AttemptAnalysis object."
    tool_name = _tool_name(kind)
    return Scenario(
        id=f"submission-{kind}",
        agents=ScenarioAgents(),
        task=TaskSpec(user_task="Submit structured data.", red_team_task="Submit structured data."),
        resources=[],
        canaries=[],
        sinks=[],
        tool_interface=ToolInterface(
            servers=[
                ToolServerSpec(
                    name=SUBMISSION_SERVER_NAME,
                    tools=[
                        ToolSpec(
                            name=tool_name,
                            description=description,
                            args_schema=model.model_json_schema(),
                        )
                    ],
                )
            ]
        ),
        tool_impls=[
            ToolImplSpec(
                tool=f"{SUBMISSION_SERVER_NAME}.{tool_name}",
                body='return ToolResult(content="submission accepted")',
            )
        ],
    )


def _tool_name(kind: SubmissionKind) -> str:
    if kind == "user_task":
        return SUBMIT_USER_TASK_TOOL
    if kind == "scenario":
        return SUBMIT_SCENARIO_TOOL
    return SUBMIT_ANALYSIS_TOOL
