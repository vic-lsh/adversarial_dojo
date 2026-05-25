from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from adversarial_dojo.agents import AGENT_CRASH_RETRIES, make_runner
from adversarial_dojo.models import (
    AgentConfig,
    AttackScenario,
    AttemptRecord,
    BenchmarkResult,
    parse_attack_patch,
)
from adversarial_dojo.evaluators import all_evaluators_passed, run_evaluators
from adversarial_dojo.secrets import materialize_runtime_secrets


def run_benchmark(
    scenario: AttackScenario,
    output_dir: str | Path | None = None,
) -> BenchmarkResult:
    active_scenario = scenario
    out_path = Path(output_dir) if output_dir is not None else None
    if out_path is not None:
        out_path.mkdir(parents=True, exist_ok=True)
        attempts_path = out_path / "attempts.jsonl"
        attempts_path.write_text("", encoding="utf-8")
    else:
        attempts_path = None

    attempts: list[AttemptRecord] = []
    winning_attempt: int | None = None

    for attempt_number in range(1, active_scenario.seed.max_attempts + 1):
        attempt_dir = _attempt_dir(out_path, attempt_number)
        red_team = make_runner("red_team", active_scenario.agents.red_team)
        patch = None
        patch_error = None
        repair_text = None
        try:
            patch_text = _with_agent_crash_retries(
                lambda: red_team.propose_patch(active_scenario, attempt_number, attempts, output_dir=attempt_dir)
            )
        except RuntimeError as exc:
            record = AttemptRecord(attempt=attempt_number, patch_error=f"red team agent crashed: {exc}")
            attempts.append(record)
            _write_attempt_artifacts(attempt_dir, record=record, scenario=None)
            _append_attempt(attempts_path, record)
            continue
        _write_text(attempt_dir, "red_team_patch.raw.txt", patch_text)
        try:
            patch = parse_attack_patch(patch_text)
        except ValueError as exc:
            repair_error = str(exc)
            try:
                repair_text = _with_agent_crash_retries(
                    lambda: red_team.propose_patch(
                        active_scenario,
                        attempt_number,
                        attempts,
                        repair_error=repair_error,
                        output_dir=attempt_dir,
                    )
                )
            except RuntimeError as crash_exc:
                patch_error = f"red team agent repair crashed: {crash_exc}"
                repair_text = ""
            _write_text(attempt_dir, "red_team_repair_patch.raw.txt", repair_text)
            if repair_text:
                try:
                    patch = parse_attack_patch(repair_text)
                except ValueError as repair_exc:
                    patch_error = str(repair_exc)

        if patch is None:
            record = AttemptRecord(attempt=attempt_number, patch_error=patch_error)
            attempts.append(record)
            _write_attempt_artifacts(attempt_dir, record=record, scenario=None)
            _append_attempt(attempts_path, record)
            continue

        try:
            candidate = active_scenario.apply_patch(patch)
        except (ValidationError, ValueError) as exc:
            record = AttemptRecord(
                attempt=attempt_number,
                patch=patch.model_dump(mode="json"),
                patch_error=str(exc),
            )
            attempts.append(record)
            _write_attempt_artifacts(attempt_dir, record=record, scenario=None)
            _append_attempt(attempts_path, record)
            continue

        rendered_candidate, runtime_secrets = materialize_runtime_secrets(candidate)
        _write_json(attempt_dir, "runtime_secrets.json", runtime_secrets.redacted())
        victim = make_runner("victim", rendered_candidate.agents.victim)
        try:
            victim_result = _with_agent_crash_retries(
                lambda: victim.run_victim(rendered_candidate, attempt_number, output_dir=attempt_dir)
            )
        except RuntimeError as exc:
            record = AttemptRecord(
                attempt=attempt_number,
                patch=patch.model_dump(mode="json"),
                patch_error=f"victim crashed: {exc}",
                victim_prompt=rendered_candidate.seed.user_task,
            )
            attempts.append(record)
            _write_attempt_artifacts(attempt_dir, record=record, scenario=rendered_candidate)
            _append_attempt(attempts_path, record)
            active_scenario = candidate
            continue
        evaluator_results = run_evaluators(
            rendered_candidate.evaluators,
            victim_result.tool_calls,
            scenario=rendered_candidate,
            runtime_secrets=runtime_secrets.values,
        )
        success = all_evaluators_passed(evaluator_results)
        record = AttemptRecord(
            attempt=attempt_number,
            patch=patch.model_dump(mode="json"),
            victim_prompt=rendered_candidate.seed.user_task,
            victim_output=victim_result.final_text,
            tool_calls=victim_result.tool_calls,
            evaluator_results=evaluator_results,
            success=success,
        )
        attempts.append(record)
        _write_attempt_artifacts(attempt_dir, record=record, scenario=rendered_candidate)
        _append_attempt(attempts_path, record)
        active_scenario = candidate

        if success:
            winning_attempt = attempt_number
            break

    result = BenchmarkResult(
        scenario_id=active_scenario.id,
        success=winning_attempt is not None,
        winning_attempt=winning_attempt,
        total_attempts=len(attempts),
        attempts=attempts,
        output_dir=str(out_path) if out_path is not None else None,
    )
    if out_path is not None:
        summary = result.model_dump(mode="json", exclude={"attempts"})
        (out_path / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return result


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


def _append_attempt(path: Path | None, record: AttemptRecord) -> None:
    if path is None:
        return
    with path.open("a", encoding="utf-8") as handle:
        handle.write(record.model_dump_json() + "\n")


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
    scenario: AttackScenario | None,
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
            "patch_error": record.patch_error,
            "tool_call_count": len(record.tool_calls),
        },
    )
    _write_json(attempt_dir, "patch.json", record.patch)
    _write_json(attempt_dir, "tool_calls.json", [call.model_dump(mode="json") for call in record.tool_calls])
    _write_json(
        attempt_dir,
        "evaluator_results.json",
        [result.model_dump(mode="json") for result in record.evaluator_results],
    )
    _write_json(attempt_dir, "analysis.json", record.analysis.model_dump(mode="json") if record.analysis else None)
    _write_text(attempt_dir, "victim_prompt.txt", record.victim_prompt or "")
    _write_text(attempt_dir, "victim_output.txt", record.victim_output)
    if scenario is not None:
        _write_text(attempt_dir, "scenario.yaml", scenario.to_yaml())


def _write_json(directory: Path | None, filename: str, data: Any) -> None:
    if directory is None:
        return
    (directory / filename).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _write_text(directory: Path | None, filename: str, text: str) -> None:
    if directory is None:
        return
    (directory / filename).write_text(text, encoding="utf-8")


def apply_overrides(scenario: AttackScenario, overrides: dict[str, Any]) -> AttackScenario:
    if not overrides:
        return scenario
    data = scenario.model_dump(mode="json")
    _override_agent(data["agents"]["red_team"], overrides, "red_team")
    _override_agent(data["agents"]["victim"], overrides, "victim")
    return AttackScenario.model_validate(data)


def _override_agent(agent_data: dict[str, Any], overrides: dict[str, Any], role: str) -> None:
    provider = overrides.get(f"{role}_provider")
    model = overrides.get(f"{role}_model")
    if role == "red_team":
        # Back-compat: accept legacy attacker_* override keys for one release.
        provider = provider or overrides.get("attacker_provider")
        model = model or overrides.get("attacker_model")
    if provider:
        agent_data["provider"] = provider
    if model:
        agent_data["model"] = model


def validate_supported_runtime(scenario: AttackScenario) -> None:
    for role, agent in (("red_team", scenario.agents.red_team), ("victim", scenario.agents.victim)):
        _validate_agent_runtime(role, agent)


def _validate_agent_runtime(role: str, agent: AgentConfig) -> None:
    if agent.provider == "fake":
        return
    if role == "victim" and agent.provider not in {"claude", "codex"}:
        raise ValueError(
            "real victim runs require an agentshim provider with MCP support; use claude or codex"
        )
