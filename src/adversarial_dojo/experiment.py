from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path

from pydantic import ValidationError

from adversarial_dojo.agents import AGENT_CRASH_RETRIES, make_runner
from adversarial_dojo.artifacts import AttackSearchRecorder, SearchArtifactStore
from adversarial_dojo.models import (
    AgentConfig,
    AttackScenario,
    AttackScenarioProposal,
    AttemptAnalysis,
    AttemptRecord,
    BenchmarkResult,
    ExperimentConfig,
    MockEnvironment,
    MockMcpServer,
    MockTool,
    parse_attack_scenario_proposal,
)
from adversarial_dojo.evaluators import all_evaluators_passed, run_evaluators
from adversarial_dojo.secrets import materialize_runtime_secrets


def run_attack_search(
    config: ExperimentConfig,
    output_dir: str | Path | None = None,
    resume: bool = False,
) -> BenchmarkResult:
    artifact_store = SearchArtifactStore.open(config, output_dir, resume=resume)
    attempts = artifact_store.load_attempts() if resume else []
    recorder = AttackSearchRecorder(attempts=attempts, artifact_store=artifact_store)
    winning_attempt: int | None = next(
        (attempt.attempt for attempt in recorder.attempts if attempt.success), None
    )
    start_attempt = (
        max((attempt.attempt for attempt in recorder.attempts), default=0) + 1
    )
    analyzer_config = _resolve_analyzer_config(config)

    for attempt_number in range(start_attempt, config.benchmark.max_attempts + 1):
        if winning_attempt is not None:
            break
        red_team = make_runner("red_team", config.agents.red_team)
        analyzer = make_runner("analyzer", analyzer_config)

        scenario, scenario_error, should_analyze_failure = _generate_prepared_scenario(
            red_team=red_team,
            config=config,
            attempt_number=attempt_number,
            attempts=recorder.attempts,
            artifact_store=artifact_store,
        )
        if scenario is None:
            record = AttemptRecord(attempt=attempt_number, patch_error=scenario_error)
            recorder.record(
                scenario=None,
                record=record,
                attempt_number=attempt_number,
                analysis_callback=_analysis_callback(
                    analyzer=analyzer,
                    config=config,
                    scenario=None,
                    record=record,
                    attempt_number=attempt_number,
                    attempt_dir=artifact_store.attempt_dir(attempt_number),
                )
                if should_analyze_failure
                else None,
            )
            continue

        rendered_scenario, record = _run_generated_scenario(
            scenario=scenario,
            attempt_number=attempt_number,
            artifact_store=artifact_store,
        )
        recorder.record(
            scenario=rendered_scenario,
            record=record,
            attempt_number=attempt_number,
            analysis_callback=_analysis_callback(
                analyzer=analyzer,
                config=config,
                scenario=rendered_scenario,
                record=record,
                attempt_number=attempt_number,
                attempt_dir=artifact_store.attempt_dir(attempt_number),
            ),
        )
        if record.success:
            winning_attempt = attempt_number
            break

    result = _build_attack_search_result(
        config, recorder.attempts, winning_attempt, artifact_store.root
    )
    artifact_store.write_summary(result)
    return result


def _analysis_callback(
    *,
    analyzer,
    config: ExperimentConfig,
    scenario: AttackScenario | None,
    record: AttemptRecord,
    attempt_number: int,
    attempt_dir: Path | None,
) -> Callable[[], None]:
    return lambda: _attach_attempt_analysis(
        analyzer=analyzer,
        config=config,
        scenario=scenario,
        record=record,
        attempt_number=attempt_number,
        attempt_dir=attempt_dir,
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


def _generate_prepared_scenario(
    *,
    red_team,
    config: ExperimentConfig,
    attempt_number: int,
    attempts: list[AttemptRecord],
    artifact_store: SearchArtifactStore,
) -> tuple[AttackScenario | None, str | None, bool]:
    try:
        raw_scenario = _with_agent_crash_retries(
            lambda: red_team.propose_scenario(
                config,
                attempt_number,
                attempts,
                output_dir=artifact_store.attempt_dir(attempt_number),
            )
        )
    except RuntimeError as exc:
        return None, f"red team agent crashed: {exc}", False

    artifact_store.write_raw_scenario(attempt_number, raw_scenario)
    try:
        return (
            _prepare_generated_scenario(
                parse_attack_scenario_proposal(raw_scenario),
                config,
                attempt_number=attempt_number,
            ),
            None,
            True,
        )
    except (KeyError, ValueError, ValidationError) as exc:
        return _repair_generated_scenario(
            red_team=red_team,
            config=config,
            attempt_number=attempt_number,
            attempts=attempts,
            artifact_store=artifact_store,
            repair_error=str(exc),
        )


def _repair_generated_scenario(
    *,
    red_team,
    config: ExperimentConfig,
    attempt_number: int,
    attempts: list[AttemptRecord],
    artifact_store: SearchArtifactStore,
    repair_error: str,
) -> tuple[AttackScenario | None, str | None, bool]:
    scenario_error = None
    try:
        repaired = _with_agent_crash_retries(
            lambda: red_team.propose_scenario(
                config,
                attempt_number,
                attempts,
                repair_error=repair_error,
                output_dir=artifact_store.attempt_dir(attempt_number),
            )
        )
    except RuntimeError as crash_exc:
        scenario_error = f"red team agent repair crashed: {crash_exc}"
        repaired = ""
    artifact_store.write_repair_scenario(attempt_number, repaired)
    if repaired:
        try:
            scenario = _prepare_generated_scenario(
                parse_attack_scenario_proposal(repaired),
                config,
                attempt_number=attempt_number,
            )
            return scenario, None, True
        except (KeyError, ValueError, ValidationError) as repair_exc:
            scenario_error = str(repair_exc)
    return None, scenario_error, True


def _run_generated_scenario(
    *,
    scenario: AttackScenario,
    attempt_number: int,
    artifact_store: SearchArtifactStore,
) -> tuple[AttackScenario, AttemptRecord]:
    rendered_scenario, runtime_secrets = materialize_runtime_secrets(scenario)
    artifact_store.write_runtime_secrets(attempt_number, runtime_secrets.redacted())
    victim = make_runner("victim", rendered_scenario.agents.victim)
    try:
        victim_result = _with_agent_crash_retries(
            lambda: victim.run_victim(
                rendered_scenario,
                attempt_number,
                output_dir=artifact_store.attempt_dir(attempt_number),
            )
        )
    except RuntimeError as exc:
        return rendered_scenario, AttemptRecord(
            attempt=attempt_number,
            patch_error=f"victim crashed: {exc}",
            victim_prompt=rendered_scenario.seed.user_task,
        )

    evaluator_results = run_evaluators(
        rendered_scenario.evaluators,
        victim_result.tool_calls,
        scenario=rendered_scenario,
        runtime_secrets=runtime_secrets.values,
    )
    return rendered_scenario, AttemptRecord(
        attempt=attempt_number,
        patch=None,
        victim_prompt=rendered_scenario.seed.user_task,
        victim_output=victim_result.final_text,
        tool_calls=victim_result.tool_calls,
        evaluator_results=evaluator_results,
        success=all_evaluators_passed(evaluator_results),
    )


def _build_attack_search_result(
    config: ExperimentConfig,
    attempts: list[AttemptRecord],
    winning_attempt: int | None,
    out_path: Path | None,
) -> BenchmarkResult:
    return BenchmarkResult(
        scenario_id=config.id,
        success=winning_attempt is not None,
        winning_attempt=winning_attempt,
        total_attempts=len(attempts),
        attempts=attempts,
        output_dir=str(out_path) if out_path is not None else None,
    )


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


def validate_supported_config(config: ExperimentConfig) -> None:
    for role, agent in (
        ("red_team", config.agents.red_team),
        ("victim", config.agents.victim),
    ):
        _validate_agent_runtime(role, agent)


def _prepare_generated_scenario(
    proposal: AttackScenarioProposal, config: ExperimentConfig, *, attempt_number: int
) -> AttackScenario:
    scenario = proposal.to_attack_scenario(
        id=f"{config.id}-attempt-{attempt_number}",
        agents=config.agents,
    )
    data = scenario.model_dump(mode="json")
    if config.tool_surface is not None:
        data["environment"] = _apply_fixed_tool_surface(
            scenario.environment, config.tool_surface
        ).model_dump(mode="json")
    prepared = AttackScenario.model_validate(data)
    _validate_generated_scenario(prepared, config)
    return prepared


def _apply_fixed_tool_surface(
    generated: MockEnvironment, fixed_surface: MockEnvironment
) -> MockEnvironment:
    fixed_servers = {server.name: server for server in fixed_surface.mcp_servers}
    generated_servers = {server.name: server for server in generated.mcp_servers}

    unknown_servers = sorted(set(generated_servers) - set(fixed_servers))
    if unknown_servers:
        raise ValueError(
            "generated scenario uses servers outside fixed tool_surface: "
            + ", ".join(unknown_servers)
        )

    materialized_servers: list[MockMcpServer] = []
    for fixed_server in fixed_surface.mcp_servers:
        generated_server = generated_servers.get(fixed_server.name)
        generated_tools = (
            {tool.name: tool for tool in generated_server.tools}
            if generated_server is not None
            else {}
        )
        fixed_tool_names = {tool.name for tool in fixed_server.tools}
        unknown_tools = sorted(set(generated_tools) - fixed_tool_names)
        if unknown_tools:
            qualified = ", ".join(
                f"{fixed_server.name}.{tool}" for tool in unknown_tools
            )
            raise ValueError(
                "generated scenario uses tools outside fixed tool_surface: " + qualified
            )

        tools: list[MockTool] = []
        for fixed_tool in fixed_server.tools:
            generated_tool = generated_tools.get(fixed_tool.name)
            responses = (
                generated_tool.responses
                if generated_tool is not None
                else fixed_tool.responses
            )
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


def _validate_generated_scenario(
    scenario: AttackScenario, config: ExperimentConfig
) -> None:
    constraints = config.benchmark.constraints
    server_count = len(scenario.environment.mcp_servers)
    if server_count == 0:
        raise ValueError(
            "generated scenario must define at least one mocked MCP server"
        )
    # Server-count and tools-per-server caps only constrain from-scratch generation.
    # When a fixed tool_surface is supplied, the surface itself pins these dimensions.
    has_fixed_surface = config.tool_surface is not None
    if not has_fixed_surface and server_count > constraints.max_mcp_servers:
        raise ValueError(
            f"generated scenario defines {server_count} MCP servers, max is {constraints.max_mcp_servers}"
        )
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
        raise ValueError(
            "real victim runs require an agentshim provider with MCP support; use claude or codex"
        )
