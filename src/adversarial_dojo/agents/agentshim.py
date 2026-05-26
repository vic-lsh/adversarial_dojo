from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
import signal
import threading
from typing import Any, Callable

from adversarial_dojo.agents.prompts import (
    analysis_prompt,
    scenario_generation_prompt,
    user_task_generation_prompt,
)
from adversarial_dojo.agents.trajectories import AgentTrajectoryRecorder
from adversarial_dojo.agents.constants import AGENT_TURN_TIMEOUT_SECONDS
from adversarial_dojo.agents.utils import (
    generate_in_session,
    make_coding_agent,
    prepare_agent_workspace,
    prepare_victim_workspace,
    victim_sandbox_config,
)
from adversarial_dojo.config import AgentConfig, ExperimentConfig
from adversarial_dojo.records import AgentRunResult, AttemptAnalysis, AttemptRecord
from adversarial_dojo.red_team_submission import (
    RedTeamSubmissionHarness,
    SubmissionKind,
    submission_to_text,
    submission_tool_name,
)
from adversarial_dojo.scenario import Scenario, UserTaskProposal
from adversarial_dojo.validation import (
    scenario_validation_error_text,
    user_task_validation_error_text,
)


@dataclass
class AgentshimRunner:
    role: str
    config: AgentConfig

    def run_victim(
        self,
        scenario: Scenario,
        attempt: int,
        output_dir: Path | None = None,
    ) -> AgentRunResult:
        from agentshim import CodingAgent

        from adversarial_dojo.resource_mcp_harness import ResourceMcpHarness

        event_recorder = AgentTrajectoryRecorder("victim", output_dir)
        with ResourceMcpHarness(scenario, output_dir=output_dir, attempt=attempt) as harness:
            victim_cwd = prepare_victim_workspace(output_dir, attempt)
            sandbox = victim_sandbox_config(victim_cwd) if self.config.provider == "claude" else None
            agent = make_coding_agent(
                CodingAgent,
                self.config,
                mcp_servers=harness.mcp_servers,
                event_handler=event_recorder,
                sandbox=sandbox,
            )
            final_text = agent.generate(
                scenario.task.user_task,
                cwd=str(victim_cwd),
                timeout=AGENT_TURN_TIMEOUT_SECONDS,
                silent=True,
            )
            calls = harness.collect_calls()
            leaks = harness.collect_leaks()
            resource_state = harness.final_resource_state()
        if not calls:
            calls = event_recorder.tool_events
        return AgentRunResult(
            final_text=final_text,
            tool_calls=calls,
            leak_events=leaks,
            resource_state=resource_state,
        )

    def propose_scenario(
        self,
        config: ExperimentConfig,
        attempt: int,
        previous_attempts: list[Any],
        user_task: UserTaskProposal,
        repair_error: str | None = None,
        output_dir: Path | None = None,
    ) -> str:
        from agentshim import CodingAgent

        workspace = prepare_agent_workspace(
            role="red_team",
            config=config,
            attempt=attempt,
            output_dir=output_dir,
            previous_attempts=previous_attempts,
        )
        prompt = scenario_generation_prompt(
            config,
            attempt,
            previous_attempts,
            user_task=user_task.user_task,
            repair_error=repair_error,
            output_dir=output_dir,
            previous_attempts_workspace="previous_attempts",
        )
        event_recorder = AgentTrajectoryRecorder("red_team", output_dir)
        return generate_red_team_submission(
            CodingAgent,
            self.config,
            prompt=prompt,
            kind="scenario",
            attempt=attempt,
            output_dir=output_dir,
            event_recorder=event_recorder,
            validator=lambda text: scenario_validation_error_text(text, config),
            cwd=workspace,
        )

    def propose_user_task(
        self,
        config: ExperimentConfig,
        attempt: int,
        output_dir: Path | None = None,
    ) -> str:
        from agentshim import CodingAgent

        workspace = prepare_agent_workspace(
            role="user_task",
            config=config,
            attempt=attempt,
            output_dir=output_dir,
        )
        prompt = user_task_generation_prompt(config, attempt)
        event_recorder = AgentTrajectoryRecorder("user_task", output_dir)
        return generate_red_team_submission(
            CodingAgent,
            self.config,
            prompt=prompt,
            kind="user_task",
            attempt=attempt,
            output_dir=output_dir,
            event_recorder=event_recorder,
            validator=user_task_validation_error_text,
            cwd=workspace,
        )

    def analyze_attempt(
        self,
        config: ExperimentConfig,
        scenario: Scenario | None,
        record: AttemptRecord,
        attempt: int,
        attempt_dir: Path,
        output_dir: Path | None = None,
    ) -> AttemptAnalysis:
        from agentshim import CodingAgent

        workspace = prepare_agent_workspace(
            role="analyzer",
            config=config,
            attempt=attempt,
            output_dir=output_dir,
            attempt_dir=attempt_dir,
        )
        prompt = analysis_prompt(
            config=config,
            scenario=scenario,
            record=record,
            attempt=attempt,
            attempt_dir=attempt_dir,
            workspace_attempt_path="current_attempt",
        )
        event_recorder = AgentTrajectoryRecorder("analyzer", output_dir)
        raw = generate_red_team_submission(
            CodingAgent,
            self.config,
            prompt=prompt,
            kind="analysis",
            attempt=attempt,
            output_dir=output_dir,
            event_recorder=event_recorder,
            cwd=workspace,
        )
        from adversarial_dojo.records import parse_attempt_analysis

        return parse_attempt_analysis(raw)


def generate_red_team_submission(
    coding_agent_cls,
    config: AgentConfig,
    *,
    prompt: str,
    kind: SubmissionKind,
    attempt: int,
    output_dir: Path | None,
    event_recorder: AgentTrajectoryRecorder,
    validator: Callable[[str], str | None] | None = None,
    max_validation_rounds: int = 3,
    cwd: Path | str = ".",
    turn_timeout_seconds: float = AGENT_TURN_TIMEOUT_SECONDS,
) -> str:
    with RedTeamSubmissionHarness(kind, output_dir=output_dir, attempt=attempt) as harness:
        agent = make_coding_agent(
            coding_agent_cls,
            config,
            mcp_servers=harness.mcp_servers,
            event_handler=event_recorder,
        )
        next_prompt = prompt
        final_text = ""
        last_submission_text = ""
        for round_index in range(max_validation_rounds + 1):
            call_start = harness.call_count()
            event_start = len(event_recorder.tool_events)
            with _agent_turn_time_limit(turn_timeout_seconds):
                final_text = generate_in_session(
                    agent,
                    next_prompt,
                    cwd=cwd,
                    timeout_seconds=turn_timeout_seconds,
                )
            submission = harness.collect_submission_since(
                call_start=call_start,
                extra_call_start=event_start,
                extra_calls=event_recorder.tool_events,
            )
            if submission is None:
                _record_validation_round(
                    output_dir,
                    kind,
                    round_index,
                    "missing_submission",
                    missing_submission_prompt(kind),
                )
                if round_index >= max_validation_rounds:
                    raise RuntimeError(missing_submission_prompt(kind))
                next_prompt = missing_submission_prompt(kind)
                continue

            last_submission_text = submission_to_text(submission)
            validation_error = validator(last_submission_text) if validator else None
            if validation_error is None:
                _record_validation_round(output_dir, kind, round_index, "valid", "")
                return last_submission_text

            _record_validation_round(output_dir, kind, round_index, "invalid", validation_error)
            if round_index >= max_validation_rounds:
                return last_submission_text
            next_prompt = validation_failure_prompt(kind, validation_error)
        return last_submission_text or final_text


@contextmanager
def _agent_turn_time_limit(seconds: float):
    if seconds <= 0 or threading.current_thread() is not threading.main_thread():
        yield
        return

    def handle_timeout(signum: int, frame) -> None:
        del signum, frame
        raise TimeoutError(f"agent turn exceeded {seconds:.1f}s timeout")

    previous_handler = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, handle_timeout)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)


def missing_submission_prompt(kind: SubmissionKind) -> str:
    return (
        f"You did not call the required MCP tool `{submission_tool_name(kind)}`. "
        "Call that tool now with the complete object that matches its input schema. "
        "Do not answer with YAML, JSON, Markdown, or explanatory text."
    )


def validation_failure_prompt(kind: SubmissionKind, validation_error: str) -> str:
    return (
        f"Your submitted `{submission_tool_name(kind)}` payload failed framework validation.\n\n"
        f"{validation_error}\n\n"
        f"Call `{submission_tool_name(kind)}` again with the complete corrected object. "
        "Do not answer with YAML, JSON, Markdown, or explanatory text."
    )


def _record_validation_round(
    output_dir: Path | None,
    kind: SubmissionKind,
    round_index: int,
    status: str,
    message: str,
) -> None:
    if output_dir is None:
        return
    path = output_dir / f"{kind}_validation_rounds.jsonl"
    payload = {
        "round": round_index,
        "status": status,
        "message": message,
    }
    import json

    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload) + "\n")
