from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from adversarial_dojo.agents import make_runner
from adversarial_dojo.models import (
    AgentConfig,
    AttackScenario,
    AttemptRecord,
    BenchmarkResult,
    ExperimentConfig,
    parse_attack_scenario,
)
from adversarial_dojo.oracles import all_oracles_passed, evaluate_oracles
from adversarial_dojo.runner import (
    _append_attempt,
    _attempt_dir,
    _override_agent,
    _write_attempt_artifacts,
    _write_json,
    _write_text,
)
from adversarial_dojo.secrets import materialize_runtime_secrets


def run_attack_search(
    config: ExperimentConfig,
    overrides: dict[str, Any] | None = None,
    output_dir: str | Path | None = None,
) -> BenchmarkResult:
    active_config = apply_config_overrides(config, overrides or {})
    validate_supported_config(active_config)
    out_path = Path(output_dir) if output_dir is not None else None
    if out_path is not None:
        out_path.mkdir(parents=True, exist_ok=True)
        attempts_path = out_path / "attempts.jsonl"
        attempts_path.write_text("", encoding="utf-8")
        _write_json(out_path, "config.json", active_config.model_dump(mode="json"))
    else:
        attempts_path = None

    attempts: list[AttemptRecord] = []
    winning_attempt: int | None = None

    for attempt_number in range(1, active_config.benchmark.max_attempts + 1):
        attempt_dir = _attempt_dir(out_path, attempt_number)
        attacker = make_runner("attacker", active_config.agents.attacker)
        scenario = None
        scenario_error = None
        raw_scenario = attacker.propose_scenario(active_config, attempt_number, attempts, output_dir=attempt_dir)
        _write_text(attempt_dir, "attacker_scenario.raw.txt", raw_scenario)
        try:
            scenario = _prepare_generated_scenario(parse_attack_scenario(raw_scenario), active_config)
        except (ValueError, ValidationError) as exc:
            repaired = attacker.propose_scenario(
                active_config,
                attempt_number,
                attempts,
                repair_error=str(exc),
                output_dir=attempt_dir,
            )
            _write_text(attempt_dir, "attacker_repair_scenario.raw.txt", repaired)
            try:
                scenario = _prepare_generated_scenario(parse_attack_scenario(repaired), active_config)
            except (ValueError, ValidationError) as repair_exc:
                scenario_error = str(repair_exc)

        if scenario is None:
            record = AttemptRecord(attempt=attempt_number, patch_error=scenario_error)
            attempts.append(record)
            _write_attempt_artifacts(attempt_dir, record=record, scenario=None)
            _append_attempt(attempts_path, record)
            continue

        rendered_scenario, runtime_secrets = materialize_runtime_secrets(scenario)
        _write_json(attempt_dir, "runtime_secrets.json", runtime_secrets.redacted())
        victim = make_runner("victim", rendered_scenario.agents.victim)
        victim_result = victim.run_victim(rendered_scenario, attempt_number, output_dir=attempt_dir)
        oracle_results = evaluate_oracles(
            rendered_scenario.oracles,
            victim_result.tool_calls,
            scenario=rendered_scenario,
            runtime_secrets=runtime_secrets.values,
        )
        success = all_oracles_passed(oracle_results)
        record = AttemptRecord(
            attempt=attempt_number,
            patch=None,
            victim_prompt=rendered_scenario.seed.user_task,
            victim_output=victim_result.final_text,
            tool_calls=victim_result.tool_calls,
            oracle_results=oracle_results,
            success=success,
        )
        attempts.append(record)
        _write_attempt_artifacts(attempt_dir, record=record, scenario=rendered_scenario)
        _append_attempt(attempts_path, record)
        if success:
            winning_attempt = attempt_number
            break

    result = BenchmarkResult(
        scenario_id=active_config.id,
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


def apply_config_overrides(config: ExperimentConfig, overrides: dict[str, Any]) -> ExperimentConfig:
    if not overrides:
        return config
    data = config.model_dump(mode="json")
    _override_agent(data["agents"]["attacker"], overrides, "attacker")
    _override_agent(data["agents"]["victim"], overrides, "victim")
    return ExperimentConfig.model_validate(data)


def validate_supported_config(config: ExperimentConfig) -> None:
    for role, agent in (("attacker", config.agents.attacker), ("victim", config.agents.victim)):
        _validate_agent_runtime(role, agent)


def _prepare_generated_scenario(scenario: AttackScenario, config: ExperimentConfig) -> AttackScenario:
    data = scenario.model_dump(mode="json")
    data["agents"] = config.agents.model_dump(mode="json")
    data["seed"]["max_attempts"] = 1
    prepared = AttackScenario.model_validate(data)
    _validate_generated_scenario(prepared, config)
    return prepared


def _validate_generated_scenario(scenario: AttackScenario, config: ExperimentConfig) -> None:
    constraints = config.benchmark.constraints
    server_count = len(scenario.environment.mcp_servers)
    if server_count == 0:
        raise ValueError("generated scenario must define at least one mocked MCP server")
    if server_count > constraints.max_mcp_servers:
        raise ValueError(f"generated scenario defines {server_count} MCP servers, max is {constraints.max_mcp_servers}")
    for server in scenario.environment.mcp_servers:
        tool_count = len(server.tools)
        if tool_count > constraints.max_tools_per_server:
            raise ValueError(
                f"generated MCP server {server.name} defines {tool_count} tools, "
                f"max is {constraints.max_tools_per_server}"
            )
        for tool in server.tools:
            for response in tool.responses:
                response_chars = len(response.content)
                if response.structured_content is not None:
                    response_chars += len(json.dumps(response.structured_content))
                if response_chars > constraints.max_tool_response_chars:
                    raise ValueError(
                        f"generated response for {server.name}.{tool.name} is {response_chars} chars, "
                        f"max is {constraints.max_tool_response_chars}"
                    )


def _validate_agent_runtime(role: str, agent: AgentConfig) -> None:
    if agent.provider == "fake":
        return
    if role == "victim" and agent.provider not in {"claude", "codex"}:
        raise ValueError("real victim runs require an agentshim provider with MCP support; use claude or codex")
