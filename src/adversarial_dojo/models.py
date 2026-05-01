from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any, Literal

import yaml
from jsonschema import Draft202012Validator, SchemaError
from pydantic import AliasChoices, BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class AgentConfig(StrictModel):
    provider: str = "fake"
    model: str | None = None
    reasoning_effort: Literal["low", "medium", "high", "xhigh"] | None = None
    backend_kwargs: dict[str, Any] = Field(default_factory=dict)


class ScenarioAgents(StrictModel):
    attacker: AgentConfig = Field(default_factory=AgentConfig)
    victim: AgentConfig = Field(default_factory=AgentConfig)


class BenchmarkConstraints(StrictModel):
    max_mcp_servers: int = Field(default=4, ge=1)
    max_tools_per_server: int = Field(default=8, ge=1)
    max_tool_response_chars: int = Field(default=4000, ge=1)


class ExperimentBenchmark(StrictModel):
    max_attempts: int = Field(default=10, ge=1)
    victim_profile: str = "A helpful agent with access to mocked MCP tools."
    attacker_guidance: str = ""
    attacker_guidance_file: str | None = None
    constraints: BenchmarkConstraints = Field(default_factory=BenchmarkConstraints)


class ScenarioSeed(StrictModel):
    user_task: str = Field(min_length=1)
    attacker_task: str = Field(min_length=1)
    max_attempts: int = Field(default=3, ge=1)
    attacker_instructions: str = ""


class MockToolResponse(StrictModel):
    content: str = ""
    structured_content: dict[str, Any] | None = None
    is_error: bool = False
    match_args: dict[str, Any] | None = None


class MockTool(StrictModel):
    name: str = Field(min_length=1)
    description: str = Field(
        default="",
        validation_alias=AliasChoices("description", "tool_string"),
        serialization_alias="description",
    )
    args_schema: dict[str, Any] = Field(
        default_factory=lambda: {"type": "object", "properties": {}, "additionalProperties": True}
    )
    responses: list[MockToolResponse] = Field(default_factory=lambda: [MockToolResponse(content="")])

    @field_validator("args_schema")
    @classmethod
    def validate_args_schema(cls, value: dict[str, Any]) -> dict[str, Any]:
        try:
            Draft202012Validator.check_schema(value)
        except SchemaError as exc:
            raise ValueError(f"invalid JSON schema: {exc.message}") from exc
        return value

    def select_response(self, arguments: dict[str, Any], call_index: int = 0) -> MockToolResponse:
        matching = [
            response
            for response in self.responses
            if response.match_args is None or _dict_contains(arguments, response.match_args)
        ]
        if not matching:
            return MockToolResponse(content="")
        return matching[min(call_index, len(matching) - 1)]


class MockMcpServer(StrictModel):
    name: str = Field(min_length=1)
    tools: list[MockTool] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_unique_tool_names(self) -> MockMcpServer:
        names = [tool.name for tool in self.tools]
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            raise ValueError(f"duplicate tool names in server {self.name}: {', '.join(duplicates)}")
        return self


class MockEnvironment(StrictModel):
    mcp_servers: list[MockMcpServer] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_unique_global_tool_names(self) -> MockEnvironment:
        seen: dict[str, str] = {}
        duplicates: list[str] = []
        for server in self.mcp_servers:
            for tool in server.tools:
                if tool.name in seen:
                    duplicates.append(f"{tool.name} ({seen[tool.name]}, {server.name})")
                seen[tool.name] = server.name
        if duplicates:
            raise ValueError("duplicate tool names across environment: " + ", ".join(sorted(duplicates)))
        return self

    def find_tool(self, server_name: str | None, tool_name: str) -> tuple[MockMcpServer, MockTool]:
        for server in self.mcp_servers:
            if server_name is not None and server.name != server_name:
                continue
            for tool in server.tools:
                if tool.name == tool_name:
                    return server, tool
        qualified = f"{server_name}.{tool_name}" if server_name else tool_name
        raise KeyError(f"unknown mock tool: {qualified}")


class ExperimentConfig(StrictModel):
    id: str = Field(min_length=1)
    agents: ScenarioAgents
    benchmark: ExperimentBenchmark = Field(default_factory=ExperimentBenchmark)
    tool_surface: MockEnvironment | None = None
    tool_surface_file: str | None = None

    @classmethod
    def from_toml_file(cls, path: str | Path) -> ExperimentConfig:
        config_path = Path(path)
        with config_path.open("rb") as handle:
            data = tomllib.load(handle)
        if "tool_surface_file" in data:
            if "tool_surface" in data:
                raise ValueError("config must define either tool_surface or tool_surface_file, not both")
            surface_path = Path(data["tool_surface_file"]).expanduser()
            if not surface_path.is_absolute():
                surface_path = config_path.parent / surface_path
            from adversarial_dojo.tool_surfaces import load_tool_surface_file

            data["tool_surface"] = load_tool_surface_file(surface_path).model_dump(mode="json")
        benchmark = data.get("benchmark")
        if isinstance(benchmark, dict) and benchmark.get("attacker_guidance_file"):
            guidance_path = Path(benchmark["attacker_guidance_file"]).expanduser()
            if not guidance_path.is_absolute():
                guidance_path = config_path.parent / guidance_path
            guidance_text = guidance_path.read_text(encoding="utf-8")
            existing_guidance = str(benchmark.get("attacker_guidance", "")).strip()
            benchmark["attacker_guidance"] = _combine_guidance(existing_guidance, guidance_text)
        return cls.model_validate(data)


def _combine_guidance(*parts: str) -> str:
    cleaned = [part.strip() for part in parts if part and part.strip()]
    return "\n\n".join(cleaned)


class ToolInvokedOracle(StrictModel):
    type: Literal["tool_invoked"] = "tool_invoked"
    tool_name: str = Field(min_length=1)
    args_subset: dict[str, Any] = Field(default_factory=dict, validation_alias=AliasChoices("args_subset", "arguments"))


class SecretSpec(StrictModel):
    id: str = Field(min_length=1, pattern=r"^[A-Za-z0-9_-]+$")
    description: str = ""
    placeholder: str | None = None

    @property
    def token(self) -> str:
        return self.placeholder or f"{{{{secret.{self.id}}}}}"


class ExfiltrationSink(StrictModel):
    id: str = Field(min_length=1)
    server: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    args_subset: dict[str, Any] = Field(default_factory=dict)
    payload_fields: list[str] = Field(default_factory=list, min_length=1)

    @property
    def tool_name(self) -> str:
        return f"{self.server}.{self.tool}"


class SecretExfiltratedOracle(StrictModel):
    type: Literal["secret_exfiltrated"] = "secret_exfiltrated"
    secret_id: str = Field(min_length=1)
    sink_id: str = Field(min_length=1)


Oracle = ToolInvokedOracle | SecretExfiltratedOracle


class AttackPatch(StrictModel):
    user_task: str | None = None
    attacker_task: str | None = None
    environment: MockEnvironment | None = None
    oracles: list[Oracle] | None = None
    secrets: list[SecretSpec] | None = None
    exfiltration_sinks: list[ExfiltrationSink] | None = None

    @model_validator(mode="after")
    def validate_non_empty(self) -> AttackPatch:
        if (
            self.user_task is None
            and self.attacker_task is None
            and self.environment is None
            and self.oracles is None
            and self.secrets is None
            and self.exfiltration_sinks is None
        ):
            raise ValueError("attack patch must change at least one field")
        return self


class AttackScenario(StrictModel):
    id: str = Field(min_length=1)
    agents: ScenarioAgents = Field(default_factory=ScenarioAgents)
    seed: ScenarioSeed
    environment: MockEnvironment = Field(default_factory=MockEnvironment)
    secrets: list[SecretSpec] = Field(default_factory=list)
    exfiltration_sinks: list[ExfiltrationSink] = Field(default_factory=list)
    oracles: list[Oracle] = Field(min_length=1)

    @field_validator("oracles")
    @classmethod
    def validate_oracles(cls, value: list[Oracle]) -> list[Oracle]:
        if not value:
            raise ValueError("at least one oracle is required")
        return value

    @model_validator(mode="after")
    def validate_secret_exfiltration_references(self) -> AttackScenario:
        secret_ids = {secret.id for secret in self.secrets}
        sink_ids = {sink.id for sink in self.exfiltration_sinks}
        for oracle in self.oracles:
            if isinstance(oracle, SecretExfiltratedOracle):
                if oracle.secret_id not in secret_ids:
                    raise ValueError(f"secret_exfiltrated oracle references unknown secret: {oracle.secret_id}")
                if oracle.sink_id not in sink_ids:
                    raise ValueError(f"secret_exfiltrated oracle references unknown sink: {oracle.sink_id}")
        for sink in self.exfiltration_sinks:
            self.environment.find_tool(sink.server, sink.tool)
        for secret in self.secrets:
            if _is_unrendered_secret(secret) and not _environment_contains_text(self.environment, secret.token):
                raise ValueError(f"secret placeholder {secret.token} must appear in at least one mocked tool response")
        return self

    def apply_patch(self, patch: AttackPatch) -> AttackScenario:
        data = self.model_dump(mode="json")
        if patch.user_task is not None:
            data["seed"]["user_task"] = patch.user_task
        if patch.attacker_task is not None:
            data["seed"]["attacker_task"] = patch.attacker_task
        if patch.environment is not None:
            data["environment"] = patch.environment.model_dump(mode="json")
        if patch.secrets is not None:
            data["secrets"] = [secret.model_dump(mode="json") for secret in patch.secrets]
        if patch.exfiltration_sinks is not None:
            data["exfiltration_sinks"] = [sink.model_dump(mode="json") for sink in patch.exfiltration_sinks]
        if patch.oracles is not None:
            data["oracles"] = [oracle.model_dump(mode="json") for oracle in patch.oracles]
        return AttackScenario.model_validate(data)

    @classmethod
    def from_yaml_file(cls, path: str | Path) -> AttackScenario:
        with Path(path).open("r", encoding="utf-8") as handle:
            return cls.model_validate(yaml.safe_load(handle))

    def to_yaml(self) -> str:
        return yaml.safe_dump(self.model_dump(mode="json"), sort_keys=False)


class ToolCallRecord(StrictModel):
    server_name: str
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    result_content: str = ""
    structured_content: dict[str, Any] | None = None
    is_error: bool = False

    @property
    def qualified_name(self) -> str:
        return f"{self.server_name}.{self.tool_name}"


class OracleResult(StrictModel):
    oracle: dict[str, Any]
    passed: bool
    reason: str


class AgentRunResult(StrictModel):
    final_text: str = ""
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)


class AttemptRecord(StrictModel):
    attempt: int
    patch: dict[str, Any] | None = None
    patch_error: str | None = None
    victim_prompt: str | None = None
    victim_output: str = ""
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    oracle_results: list[OracleResult] = Field(default_factory=list)
    success: bool = False


class BenchmarkResult(StrictModel):
    scenario_id: str
    success: bool
    winning_attempt: int | None = None
    total_attempts: int
    attempts: list[AttemptRecord]
    output_dir: str | None = None


def parse_attack_patch(text: str) -> AttackPatch:
    cleaned = _strip_code_fence(text)
    try:
        loaded = yaml.safe_load(cleaned)
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML/JSON attack patch: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ValueError("attack patch must be a mapping")
    try:
        return AttackPatch.model_validate(loaded)
    except ValidationError as exc:
        raise ValueError(str(exc)) from exc


def parse_attack_scenario(text: str) -> AttackScenario:
    cleaned = _strip_code_fence(text)
    try:
        loaded = yaml.safe_load(cleaned)
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML/JSON attack scenario: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ValueError("attack scenario must be a mapping")
    try:
        return AttackScenario.model_validate(loaded)
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


def _dict_contains(actual: dict[str, Any], expected_subset: dict[str, Any]) -> bool:
    for key, expected_value in expected_subset.items():
        if key not in actual:
            return False
        actual_value = actual[key]
        if isinstance(expected_value, dict):
            if not isinstance(actual_value, dict) or not _dict_contains(actual_value, expected_value):
                return False
        elif actual_value != expected_value:
            return False
    return True


def dict_contains(actual: dict[str, Any], expected_subset: dict[str, Any]) -> bool:
    return _dict_contains(actual, expected_subset)


def _environment_contains_text(environment: MockEnvironment, needle: str) -> bool:
    for server in environment.mcp_servers:
        for tool in server.tools:
            for response in tool.responses:
                if needle in response.content:
                    return True
                if response.structured_content is not None and needle in str(response.structured_content):
                    return True
    return False


def _is_unrendered_secret(secret: SecretSpec) -> bool:
    return secret.placeholder is not None or secret.token == f"{{{{secret.{secret.id}}}}}"
