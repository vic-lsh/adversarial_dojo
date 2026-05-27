from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from adversarial_dojo.agents import AGENT_CRASH_RETRIES, make_runner
from adversarial_dojo.config import AgentConfig, ExperimentConfig
from adversarial_dojo.records import (
    AttemptAnalysis,
    AttemptRecord,
    BenchmarkResult,
)
from adversarial_dojo.scenario import (
    Scenario,
    ScenarioProposal,
    UserTaskProposal,
    parse_scenario_proposal,
    parse_user_task_proposal,
)
from adversarial_dojo.runtime.tool_impl import ToolImplExecutor
from adversarial_dojo.validation import (
    build_scenario_from_validated_proposal,
    user_task_validation_error_text,
)


def run_attack_search(
    config: ExperimentConfig,
    output_dir: str | Path | None = None,
    resume: bool = False,
) -> BenchmarkResult:
    out_path = Path(output_dir) if output_dir is not None else None
    if out_path is not None:
        out_path.mkdir(parents=True, exist_ok=True)
        attempts_path = out_path / "attempts.jsonl"
        if not resume or not attempts_path.exists():
            attempts_path.write_text("", encoding="utf-8")
        _write_json(out_path, "config.json", config.model_dump(mode="json"))
    else:
        attempts_path = None

    attempts = _load_attempts(attempts_path) if resume else []
    winning_attempt: int | None = next(
        (attempt.attempt for attempt in attempts if attempt.success),
        None,
    )
    analyzer_config = _resolve_analyzer_config(config)
    start_attempt = max((attempt.attempt for attempt in attempts), default=0) + 1

    for attempt_number in range(start_attempt, config.benchmark.max_attempts + 1):
        if winning_attempt is not None:
            break
        attempt_dir = _attempt_dir(out_path, attempt_number)
        user_task_agent = make_runner("user_task", config.agents.user_task)
        red_team = make_runner("red_team", config.agents.red_team)
        analyzer = make_runner("analyzer", analyzer_config)

        user_task, user_task_error = _generate_user_task(
            user_task_agent=user_task_agent,
            config=config,
            attempt_number=attempt_number,
            attempt_dir=attempt_dir,
        )
        if user_task is None:
            record = AttemptRecord(
                attempt=attempt_number,
                error=user_task_error,
            )
            attempts.append(record)
            _write_attempt_artifacts(
                attempt_dir,
                record=record,
                scenario=None,
                proposal=None,
            )
            _append_attempt(attempts_path, record)
            _print_attempt_error(record, attempt_dir)
            continue

        scenario, proposal, error, should_analyze = _generate_scenario(
            red_team=red_team,
            config=config,
            attempt_number=attempt_number,
            attempts=attempts,
            attempt_dir=attempt_dir,
            user_task=user_task,
        )
        if scenario is None:
            record = AttemptRecord(
                attempt=attempt_number,
                proposal=proposal.model_dump(mode="json") if proposal else None,
                error=error,
                victim_prompt=user_task.user_task,
            )
            _attach_analysis(
                analyzer=analyzer,
                config=config,
                scenario=None,
                record=record,
                attempt_number=attempt_number,
                attempt_dir=attempt_dir,
            ) if should_analyze else None
            attempts.append(record)
            _write_attempt_artifacts(attempt_dir, record=record, scenario=None, proposal=proposal)
            _append_attempt(attempts_path, record)
            _print_attempt_error(record, attempt_dir)
            continue

        record = _run_scenario(
            scenario=scenario,
            proposal=proposal,
            attempt_number=attempt_number,
            attempt_dir=attempt_dir,
        )
        _attach_analysis(
            analyzer=analyzer,
            config=config,
            scenario=scenario,
            record=record,
            attempt_number=attempt_number,
            attempt_dir=attempt_dir,
        )
        attempts.append(record)
        _write_attempt_artifacts(attempt_dir, record=record, scenario=scenario, proposal=proposal)
        _append_attempt(attempts_path, record)
        _print_attempt_error(record, attempt_dir)
        if record.success:
            winning_attempt = attempt_number
            break

    result = BenchmarkResult(
        scenario_id=config.id,
        success=winning_attempt is not None,
        winning_attempt=winning_attempt,
        total_attempts=len(attempts),
        attempts=attempts,
        output_dir=str(out_path) if out_path is not None else None,
    )
    if out_path is not None:
        _write_json(out_path, "summary.json", result.model_dump(mode="json", exclude={"attempts"}))
    return result


def prepare_scenario(
    proposal: ScenarioProposal,
    config: ExperimentConfig,
    *,
    attempt_number: int,
    user_task: UserTaskProposal,
) -> Scenario:
    scenario = build_scenario_from_validated_proposal(
        proposal,
        config,
        attempt_number=attempt_number,
        user_task=user_task,
    )
    # Compile once during preparation so body-level errors are scenario errors,
    # not victim-runtime surprises.
    ToolImplExecutor(
        scenario.tool_impls,
        timeout_seconds=config.benchmark.constraints.tool_timeout_seconds,
    )
    return scenario


def validate_supported_config(config: ExperimentConfig) -> None:
    for role, agent in (
        ("red_team", config.agents.red_team),
        ("user_task", config.agents.user_task),
        ("victim", config.agents.victim),
    ):
        _validate_agent_runtime(role, agent)


def _generate_user_task(
    *,
    user_task_agent,
    config: ExperimentConfig,
    attempt_number: int,
    attempt_dir: Path | None,
) -> tuple[UserTaskProposal | None, str | None]:
    try:
        raw = _with_agent_crash_retries(
            lambda: user_task_agent.propose_user_task(
                config,
                attempt_number,
                output_dir=attempt_dir,
            )
        )
    except RuntimeError as exc:
        return None, _format_agent_crash("user task", exc, "user_task", attempt_dir)
    _write_text(attempt_dir, "user_task.raw.txt", raw)
    validation_error = user_task_validation_error_text(raw)
    if validation_error is not None:
        return None, validation_error
    try:
        user_task = parse_user_task_proposal(raw)
    except ValueError as exc:
        return None, f"user task proposal invalid: {exc}"
    _write_json(attempt_dir, "user_task.json", user_task.model_dump(mode="json"))
    return user_task, None


def _generate_scenario(
    *,
    red_team,
    config: ExperimentConfig,
    attempt_number: int,
    attempts: list[AttemptRecord],
    attempt_dir: Path | None,
    user_task: UserTaskProposal,
) -> tuple[Scenario | None, ScenarioProposal | None, str | None, bool]:
    try:
        raw = _with_agent_crash_retries(
            lambda: red_team.propose_scenario(
                config,
                attempt_number,
                attempts,
                user_task=user_task,
                output_dir=attempt_dir,
            )
        )
    except RuntimeError as exc:
        return None, None, _format_agent_crash("red team", exc, "red_team", attempt_dir), False
    _write_text(attempt_dir, "red_team_scenario.raw.txt", raw)
    try:
        proposal = parse_scenario_proposal(raw)
        return (
            prepare_scenario(
                proposal,
                config,
                attempt_number=attempt_number,
                user_task=user_task,
            ),
            proposal,
            None,
            True,
        )
    except (KeyError, ValueError, ValidationError) as exc:
        return _repair_scenario(
            red_team=red_team,
            config=config,
            attempt_number=attempt_number,
            attempts=attempts,
            attempt_dir=attempt_dir,
            repair_error=str(exc),
            user_task=user_task,
        )


def _repair_scenario(
    *,
    red_team,
    config: ExperimentConfig,
    attempt_number: int,
    attempts: list[AttemptRecord],
    attempt_dir: Path | None,
    repair_error: str,
    user_task: UserTaskProposal,
) -> tuple[Scenario | None, ScenarioProposal | None, str | None, bool]:
    try:
        repaired = _with_agent_crash_retries(
            lambda: red_team.propose_scenario(
                config,
                attempt_number,
                attempts,
                user_task=user_task,
                repair_error=repair_error,
                output_dir=attempt_dir,
            )
        )
    except RuntimeError as exc:
        _write_text(attempt_dir, "red_team_repair_scenario.raw.txt", "")
        return None, None, _format_agent_crash("red team repair", exc, "red_team", attempt_dir), True
    _write_text(attempt_dir, "red_team_repair_scenario.raw.txt", repaired)
    try:
        proposal = parse_scenario_proposal(repaired)
        return (
            prepare_scenario(
                proposal,
                config,
                attempt_number=attempt_number,
                user_task=user_task,
            ),
            proposal,
            None,
            True,
        )
    except (KeyError, ValueError, ValidationError) as exc:
        return None, None, str(exc), True


def _run_scenario(
    *,
    scenario: Scenario,
    proposal: ScenarioProposal | None,
    attempt_number: int,
    attempt_dir: Path | None,
) -> AttemptRecord:
    victim = make_runner("victim", scenario.agents.victim)
    try:
        victim_result = _with_agent_crash_retries(
            lambda: victim.run_victim(
                scenario,
                attempt_number,
                output_dir=attempt_dir,
            )
        )
    except RuntimeError as exc:
        return AttemptRecord(
            attempt=attempt_number,
            proposal=proposal.model_dump(mode="json") if proposal else None,
            error=_format_agent_crash("victim", exc, "victim", attempt_dir),
            victim_prompt=scenario.task.user_task,
        )
    return AttemptRecord(
        attempt=attempt_number,
        proposal=proposal.model_dump(mode="json") if proposal else None,
        victim_prompt=scenario.task.user_task,
        victim_output=victim_result.final_text,
        tool_calls=victim_result.tool_calls,
        leak_events=victim_result.leak_events,
        resource_state=victim_result.resource_state,
        success=bool(victim_result.leak_events),
    )


def _attach_analysis(
    *,
    analyzer,
    config: ExperimentConfig,
    scenario: Scenario | None,
    record: AttemptRecord,
    attempt_number: int,
    attempt_dir: Path | None,
) -> None:
    if attempt_dir is None:
        return
    try:
        record.analysis = _with_agent_crash_retries(
            lambda: analyzer.analyze_attempt(
                config=config,
                scenario=scenario,
                record=record,
                attempt=attempt_number,
                attempt_dir=attempt_dir,
                output_dir=attempt_dir,
            )
        )
    except RuntimeError as exc:
        record.analysis = AttemptAnalysis(
            failure_stage="other",
            summary="analyzer crashed",
            freeform_notes=_format_agent_crash("analyzer", exc, "analyzer", attempt_dir),
        )


def _resolve_analyzer_config(config: ExperimentConfig) -> AgentConfig:
    if config.agents.analyzer is not None:
        return config.agents.analyzer
    analyzer_config = config.agents.red_team
    print(
        "warning: analyzer agent not configured; inheriting red_team config "
        f"(provider={analyzer_config.provider}, model={analyzer_config.model}) "
        "-- consider setting [agents.analyzer] to a cheaper model",
        file=sys.stderr,
    )
    return analyzer_config


def _with_agent_crash_retries(call):
    last_exc: Exception | None = None
    for _ in range(AGENT_CRASH_RETRIES + 1):
        try:
            return call()
        except Exception as exc:
            last_exc = exc
    assert last_exc is not None
    if isinstance(last_exc, RuntimeError):
        raise last_exc
    raise RuntimeError(str(last_exc)) from last_exc


def _format_agent_crash(
    label: str,
    exc: RuntimeError,
    stream_role: str,
    attempt_dir: Path | None,
    *,
    tail_chars: int = 2000,
) -> str:
    message = f"{label} agent crashed: {exc}"
    stream_tail = _agent_stream_tail(attempt_dir, stream_role, tail_chars=tail_chars)
    if stream_tail and stream_tail not in message:
        message = f"{message}\n{stream_role}_stream tail:\n{stream_tail}"
    return message


def _agent_stream_tail(
    attempt_dir: Path | None,
    role: str,
    *,
    tail_chars: int = 2000,
) -> str:
    if attempt_dir is None:
        return ""
    path = attempt_dir / f"{role}_stream.txt"
    if not path.exists():
        return ""
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if len(text) <= tail_chars:
        return text
    return "... " + text[-tail_chars:]


def _append_attempt(path: Path | None, record: AttemptRecord) -> None:
    if path is None:
        return
    with path.open("a", encoding="utf-8") as handle:
        handle.write(record.model_dump_json() + "\n")


def _print_attempt_error(record: AttemptRecord, attempt_dir: Path | None) -> None:
    if not record.error:
        return
    location = f" ({attempt_dir})" if attempt_dir is not None else ""
    print(
        f"attempt {record.attempt:03d} failed{location}: {record.error}",
        file=sys.stderr,
        flush=True,
    )


def _load_attempts(path: Path | None) -> list[AttemptRecord]:
    if path is None or not path.exists():
        return []
    return [
        AttemptRecord.model_validate_json(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _attempt_dir(output_dir: Path | None, attempt_number: int) -> Path | None:
    if output_dir is None:
        return None
    path = output_dir / f"attempt-{attempt_number:03d}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _write_attempt_artifacts(
    attempt_dir: Path | None,
    *,
    record: AttemptRecord,
    scenario: Scenario | None,
    proposal: ScenarioProposal | None,
) -> None:
    if attempt_dir is None:
        return
    _write_json(attempt_dir, "attempt.json", record.model_dump(mode="json"))
    _write_json(
        attempt_dir,
        "metadata.json",
        {
            "attempt": record.attempt,
            "success": record.success,
            "error": record.error,
            "tool_call_count": len(record.tool_calls),
            "leak_count": len(record.leak_events),
        },
    )
    _write_json(attempt_dir, "proposal.json", proposal.model_dump(mode="json") if proposal else None)
    if proposal is not None:
        _write_text(
            attempt_dir,
            "proposal.yaml",
            json_to_yaml(proposal.model_dump(mode="json")),
        )
    _write_json(attempt_dir, "tool_calls.json", [call.model_dump(mode="json") for call in record.tool_calls])
    _write_json(attempt_dir, "leak_events.json", [event.model_dump(mode="json") for event in record.leak_events])
    _write_json(attempt_dir, "resource_store.final.json", record.resource_state)
    _write_json(attempt_dir, "analysis.json", record.analysis.model_dump(mode="json") if record.analysis else None)
    _write_text(attempt_dir, "victim_prompt.txt", record.victim_prompt or "")
    _write_text(attempt_dir, "victim_output.txt", record.victim_output)
    if scenario is not None:
        _write_json(attempt_dir, "scenario.json", scenario.model_dump(mode="json"))
        _write_text(attempt_dir, "scenario.yaml", scenario.to_yaml())
        _write_text(
            attempt_dir,
            "generated_tool_code.py",
            ToolImplExecutor(
                scenario.tool_impls,
                timeout_seconds=scenario.tool_timeout_seconds,
            ).generated_source(),
        )


def json_to_yaml(data: Any) -> str:
    import yaml

    return yaml.safe_dump(data, sort_keys=False)


def _write_json(directory: Path | None, filename: str, data: Any) -> None:
    if directory is None:
        return
    (directory / filename).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _write_text(directory: Path | None, filename: str, text: str) -> None:
    if directory is None:
        return
    (directory / filename).write_text(text, encoding="utf-8")


def _validate_agent_runtime(role: str, agent: AgentConfig) -> None:
    if agent.provider == "fake":
        return
    if role == "victim" and agent.provider not in {"claude", "codex"}:
        raise ValueError(
            "real victim runs require an agentshim provider with MCP support; use claude or codex"
        )
