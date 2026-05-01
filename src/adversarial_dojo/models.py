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
    constraints: BenchmarkConstraints = Field(default_factory=BenchmarkConstraints)


class ExperimentConfig(StrictModel):
    id: str = Field(min_length=1)
    agents: ScenarioAgents
    benchmark: ExperimentBenchmark = Field(default_factory=ExperimentBenchmark)

    @classmethod
    def from_toml_file(cls, path: str | Path) -> ExperimentConfig:
        with Path(path).open("rb") as handle:
            return cls.model_validate(tomllib.load(handle))


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


class ToolInvokedOracle(StrictModel):
    type: Literal["tool_invoked"] = "tool_invoked"
    tool_name: str = Field(min_length=1)
    args_subset: dict[str, Any] = Field(default_factory=dict, validation_alias=AliasChoices("args_subset", "arguments"))


Oracle = ToolInvokedOracle


class AttackPatch(StrictModel):
    user_task: str | None = None
    attacker_task: str | None = None
    environment: MockEnvironment | None = None
    oracles: list[Oracle] | None = None

    @model_validator(mode="after")
    def validate_non_empty(self) -> AttackPatch:
        if (
            self.user_task is None
            and self.attacker_task is None
            and self.environment is None
            and self.oracles is None
        ):
            raise ValueError("attack patch must change at least one field")
        return self


class AttackScenario(StrictModel):
    id: str = Field(min_length=1)
    agents: ScenarioAgents = Field(default_factory=ScenarioAgents)
    seed: ScenarioSeed
    environment: MockEnvironment = Field(default_factory=MockEnvironment)
    oracles: list[Oracle] = Field(min_length=1)

    @field_validator("oracles")
    @classmethod
    def validate_oracles(cls, value: list[Oracle]) -> list[Oracle]:
        if not value:
            raise ValueError("at least one oracle is required")
        return value

    def apply_patch(self, patch: AttackPatch) -> AttackScenario:
        data = self.model_dump(mode="json")
        if patch.user_task is not None:
            data["seed"]["user_task"] = patch.user_task
        if patch.attacker_task is not None:
            data["seed"]["attacker_task"] = patch.attacker_task
        if patch.environment is not None:
            data["environment"] = patch.environment.model_dump(mode="json")
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
