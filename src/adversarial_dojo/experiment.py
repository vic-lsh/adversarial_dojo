from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from adversarial_dojo.agents import AGENT_CRASH_RETRIES, make_runner
from adversarial_dojo.models import (
    AgentConfig,
    AttackScenario,
    AttemptRecord,
    AttemptAnalysis,
    BenchmarkResult,
    ExperimentConfig,
    MockEnvironment,
    MockMcpServer,
    MockTool,
    ToolInvokedOracle,
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
    output_dir: str | Path | None = None,
    resume: bool = False,
) -> BenchmarkResult:
    active_config = config
    out_path = Path(output_dir) if output_dir is not None else None
    if out_path is not None:
        out_path.mkdir(parents=True, exist_ok=True)
        attempts_path = out_path / "attempts.jsonl"
        if not resume:
            attempts_path.write_text("", encoding="utf-8")
        elif not attempts_path.exists():
            attempts_path.write_text("", encoding="utf-8")
        _write_json(out_path, "config.json", active_config.model_dump(mode="json"))
    else:
        attempts_path = None

    attempts: list[AttemptRecord] = _load_attempts(attempts_path) if resume else []
    winning_attempt: int | None = next((attempt.attempt for attempt in attempts if attempt.success), None)
    start_attempt = max((attempt.attempt for attempt in attempts), default=0) + 1
    if active_config.agents.analyzer is None:
        analyzer_config = active_config.agents.red_team
        print(
            "warning: analyzer agent not configured; inheriting red_team config "
            f"(provider={analyzer_config.provider}, model={analyzer_config.model}) "
            "-- consider setting [agents.analyzer] to a cheaper model",
            file=sys.stderr,
        )
    else:
        analyzer_config = active_config.agents.analyzer

    for attempt_number in range(start_attempt, active_config.benchmark.max_attempts + 1):
        if winning_attempt is not None:
            break
        attempt_dir = _attempt_dir(out_path, attempt_number)
        red_team = make_runner("red_team", active_config.agents.red_team)
        analyzer = make_runner("analyzer", analyzer_config)
        scenario = None
        scenario_error = None
        try:
            raw_scenario = _with_agent_crash_retries(
                lambda: red_team.propose_scenario(active_config, attempt_number, attempts, output_dir=attempt_dir)
            )
        except RuntimeError as exc:
            record = AttemptRecord(attempt=attempt_number, patch_error=f"red team agent crashed: {exc}")
            attempts.append(record)
            _write_attempt_artifacts(attempt_dir, record=record, scenario=None)
            _append_attempt(attempts_path, record)
            continue
        _write_text(attempt_dir, "red_team_scenario.raw.txt", raw_scenario)
        try:
            scenario = _prepare_generated_scenario(parse_attack_scenario(raw_scenario), active_config)
        except (KeyError, ValueError, ValidationError) as exc:
            try:
                repaired = _with_agent_crash_retries(
                    lambda: red_team.propose_scenario(
                        active_config,
                        attempt_number,
                        attempts,
                        repair_error=str(exc),
                        output_dir=attempt_dir,
                    )
                )
            except RuntimeError as crash_exc:
                scenario_error = f"red team agent repair crashed: {crash_exc}"
                repaired = ""
            _write_text(attempt_dir, "red_team_repair_scenario.raw.txt", repaired)
            if repaired:
                try:
                    scenario = _prepare_generated_scenario(parse_attack_scenario(repaired), active_config)
                except (KeyError, ValueError, ValidationError) as repair_exc:
                    scenario_error = str(repair_exc)

        if scenario is None:
            record = AttemptRecord(attempt=attempt_number, patch_error=scenario_error)
            _write_attempt_artifacts(attempt_dir, record=record, scenario=None)
            _attach_attempt_analysis(
                analyzer=analyzer,
                config=active_config,
                scenario=None,
                record=record,
                attempt_number=attempt_number,
                attempt_dir=attempt_dir,
            )
            attempts.append(record)
            _write_attempt_artifacts(attempt_dir, record=record, scenario=None)
            _append_attempt(attempts_path, record)
            continue

        rendered_scenario, runtime_secrets = materialize_runtime_secrets(scenario)
        _write_json(attempt_dir, "runtime_secrets.json", runtime_secrets.redacted())
        victim = make_runner("victim", rendered_scenario.agents.victim)
        try:
            victim_result = _with_agent_crash_retries(
                lambda: victim.run_victim(rendered_scenario, attempt_number, output_dir=attempt_dir)
            )
        except RuntimeError as exc:
            record = AttemptRecord(
                attempt=attempt_number,
                patch_error=f"victim crashed: {exc}",
                victim_prompt=rendered_scenario.seed.user_task,
            )
            _write_attempt_artifacts(attempt_dir, record=record, scenario=rendered_scenario)
            _attach_attempt_analysis(
                analyzer=analyzer,
                config=active_config,
                scenario=rendered_scenario,
                record=record,
                attempt_number=attempt_number,
                attempt_dir=attempt_dir,
            )
            attempts.append(record)
            _write_attempt_artifacts(attempt_dir, record=record, scenario=rendered_scenario)
            _append_attempt(attempts_path, record)
            continue
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
        _write_attempt_artifacts(attempt_dir, record=record, scenario=rendered_scenario)
        _attach_attempt_analysis(
            analyzer=analyzer,
            config=active_config,
            scenario=rendered_scenario,
            record=record,
            attempt_number=attempt_number,
            attempt_dir=attempt_dir,
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


def _load_attempts(path: Path | None) -> list[AttemptRecord]:
    if path is None or not path.exists():
        return []
    attempts: list[AttemptRecord] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        attempts.append(AttemptRecord.model_validate_json(line))
    return attempts


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


def _attach_attempt_analysis(
    *,
    analyzer,
    config: ExperimentConfig,
    scenario: AttackScenario | None,
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
            freeform_notes=str(exc),
        )


def apply_config_overrides(config: ExperimentConfig, overrides: dict[str, Any]) -> ExperimentConfig:
    if not overrides:
        return config
    data = config.model_dump(mode="json")
    _override_agent(data["agents"]["red_team"], overrides, "red_team")
    _override_agent(data["agents"]["victim"], overrides, "victim")
    analyzer_provider = overrides.get("analyzer_provider")
    analyzer_model = overrides.get("analyzer_model")
    if analyzer_provider or analyzer_model:
        analyzer_data = data["agents"].get("analyzer")
        if analyzer_data is None:
            # Seed analyzer config from red_team so a partial override (e.g. only
            # --analyzer-model) still produces a complete AgentConfig.
            analyzer_data = dict(data["agents"]["red_team"])
        _override_agent(analyzer_data, overrides, "analyzer")
        data["agents"]["analyzer"] = analyzer_data
    red_team_guidance = overrides.get("red_team_guidance", overrides.get("attacker_guidance"))
    if red_team_guidance is not None:
        data["benchmark"]["red_team_guidance"] = red_team_guidance
    return ExperimentConfig.model_validate(data)


def validate_supported_config(config: ExperimentConfig) -> None:
    for role, agent in (("red_team", config.agents.red_team), ("victim", config.agents.victim)):
        _validate_agent_runtime(role, agent)


def _prepare_generated_scenario(scenario: AttackScenario, config: ExperimentConfig) -> AttackScenario:
    data = scenario.model_dump(mode="json")
    data["agents"] = config.agents.model_dump(mode="json")
    data["seed"]["max_attempts"] = 1
    if config.tool_surface is not None:
        data["environment"] = _apply_fixed_tool_surface(scenario.environment, config.tool_surface).model_dump(
            mode="json"
        )
    prepared = AttackScenario.model_validate(data)
    _validate_generated_scenario(prepared, config)
    return prepared


def _apply_fixed_tool_surface(generated: MockEnvironment, fixed_surface: MockEnvironment) -> MockEnvironment:
    fixed_servers = {server.name: server for server in fixed_surface.mcp_servers}
    generated_servers = {server.name: server for server in generated.mcp_servers}

    unknown_servers = sorted(set(generated_servers) - set(fixed_servers))
    if unknown_servers:
        raise ValueError("generated scenario uses servers outside fixed tool_surface: " + ", ".join(unknown_servers))

    materialized_servers: list[MockMcpServer] = []
    for fixed_server in fixed_surface.mcp_servers:
        generated_server = generated_servers.get(fixed_server.name)
        generated_tools = {tool.name: tool for tool in generated_server.tools} if generated_server is not None else {}
        fixed_tool_names = {tool.name for tool in fixed_server.tools}
        unknown_tools = sorted(set(generated_tools) - fixed_tool_names)
        if unknown_tools:
            qualified = ", ".join(f"{fixed_server.name}.{tool}" for tool in unknown_tools)
            raise ValueError("generated scenario uses tools outside fixed tool_surface: " + qualified)

        tools: list[MockTool] = []
        for fixed_tool in fixed_server.tools:
            generated_tool = generated_tools.get(fixed_tool.name)
            responses = generated_tool.responses if generated_tool is not None else fixed_tool.responses
            tools.append(
                MockTool(
                    name=fixed_tool.name,
                    description=fixed_tool.description,
                    args_schema=fixed_tool.args_schema,
                    responses=responses,
                )
            )
        materialized_servers.append(MockMcpServer(name=fixed_server.name, tools=tools))

    return MockEnvironment(mcp_servers=materialized_servers)


def _validate_generated_scenario(scenario: AttackScenario, config: ExperimentConfig) -> None:
    constraints = config.benchmark.constraints
    server_count = len(scenario.environment.mcp_servers)
    if server_count == 0:
        raise ValueError("generated scenario must define at least one mocked MCP server")
    # Server-count and tools-per-server caps only constrain from-scratch generation.
    # When a fixed tool_surface is supplied, the surface itself pins these dimensions.
    has_fixed_surface = config.tool_surface is not None
    if not has_fixed_surface and server_count > constraints.max_mcp_servers:
        raise ValueError(f"generated scenario defines {server_count} MCP servers, max is {constraints.max_mcp_servers}")
    if has_fixed_surface:
        for oracle in scenario.oracles:
            if isinstance(oracle, ToolInvokedOracle):
                server_name, tool_name = _split_qualified_tool_name(oracle.tool_name)
                try:
                    scenario.environment.find_tool(server_name, tool_name)
                except KeyError as exc:
                    raise ValueError(f"tool_invoked oracle references tool outside fixed tool_surface: {oracle.tool_name}") from exc
    for server in scenario.environment.mcp_servers:
        tool_count = len(server.tools)
        if not has_fixed_surface and tool_count > constraints.max_tools_per_server:
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


def _split_qualified_tool_name(tool_name: str) -> tuple[str | None, str]:
    if "." not in tool_name:
        return None, tool_name
    server_name, bare_tool_name = tool_name.split(".", 1)
    return server_name, bare_tool_name


def _validate_agent_runtime(role: str, agent: AgentConfig) -> None:
    if agent.provider == "fake":
        return
    if role == "victim" and agent.provider not in {"claude", "codex"}:
        raise ValueError("real victim runs require an agentshim provider with MCP support; use claude or codex")
