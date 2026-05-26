from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, model_validator

from adversarial_dojo.common import StrictModel
from adversarial_dojo.tool_interfaces.models import ToolInterface


class AgentConfig(StrictModel):
    provider: str = "fake"
    model: str | None = None
    reasoning_effort: Literal["low", "medium", "high", "xhigh"] | None = None
    backend_kwargs: dict[str, Any] = Field(default_factory=dict)


class ScenarioAgents(StrictModel):
    user_task: AgentConfig = Field(default_factory=AgentConfig)
    red_team: AgentConfig = Field(default_factory=AgentConfig)
    victim: AgentConfig = Field(default_factory=AgentConfig)
    analyzer: AgentConfig | None = None


class BenchmarkConstraints(StrictModel):
    max_tool_result_chars: int = Field(default=4000, ge=1)
    max_tool_impl_chars: int = Field(default=8000, ge=1)
    tool_timeout_seconds: float = Field(default=2.0, gt=0)


class ExperimentBenchmark(StrictModel):
    max_attempts: int = Field(default=10, ge=1)
    victim_profile: str = "A helpful agent with access to resource-backed MCP tools."
    red_team_guidance: str = ""
    red_team_guidance_file: str | None = None
    constraints: BenchmarkConstraints = Field(default_factory=BenchmarkConstraints)


class ExperimentConfig(StrictModel):
    id: str = Field(min_length=1)
    agents: ScenarioAgents
    benchmark: ExperimentBenchmark = Field(default_factory=ExperimentBenchmark)
    tool_interface: ToolInterface | None = None
    tool_interface_file: str | None = None
    tool_interface_source_files: list[str] = Field(default_factory=list, exclude=True)

    @model_validator(mode="after")
    def validate_tool_interface_present(self) -> ExperimentConfig:
        if self.tool_interface is None:
            raise ValueError("experiment config must define tool_interface_file or tool_interface")
        return self

    @classmethod
    def from_toml_file(cls, path: str | Path) -> ExperimentConfig:
        config_path = Path(path)
        with config_path.open("rb") as handle:
            data = tomllib.load(handle)
        if "tool_interface_file" in data:
            if "tool_interface" in data:
                raise ValueError(
                    "config must define either tool_interface or tool_interface_file, not both"
                )
            interface_path = Path(data["tool_interface_file"]).expanduser()
            if not interface_path.is_absolute():
                interface_path = config_path.parent / interface_path
            from adversarial_dojo.tool_interfaces import (
                load_tool_interface_file,
                tool_interface_source_files,
            )

            data["tool_interface"] = load_tool_interface_file(interface_path).model_dump(
                mode="json"
            )
            data["tool_interface_source_files"] = [
                str(source.resolve()) for source in tool_interface_source_files(interface_path)
            ]
        benchmark = data.get("benchmark")
        guidance_file = None
        if isinstance(benchmark, dict):
            guidance_file = benchmark.get("red_team_guidance_file")
        if guidance_file:
            guidance_path = Path(guidance_file).expanduser()
            if not guidance_path.is_absolute():
                guidance_path = config_path.parent / guidance_path
            guidance_text = guidance_path.read_text(encoding="utf-8")
            existing_guidance = str(benchmark.get("red_team_guidance", "")).strip()
            benchmark["red_team_guidance"] = combine_guidance(
                existing_guidance, guidance_text
            )
            benchmark["red_team_guidance_file"] = str(guidance_file)
        return cls.model_validate(data)


def combine_guidance(*parts: str) -> str:
    cleaned = [part.strip() for part in parts if part and part.strip()]
    return "\n\n".join(cleaned)
