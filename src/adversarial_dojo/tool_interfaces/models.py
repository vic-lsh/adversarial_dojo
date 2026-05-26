from __future__ import annotations

from typing import Any

from jsonschema import Draft202012Validator, SchemaError
from pydantic import Field, field_validator, model_validator

from adversarial_dojo.common import StrictModel


class ToolSpec(StrictModel):
    name: str = Field(min_length=1)
    description: str = ""
    args_schema: dict[str, Any] = Field(
        default_factory=lambda: {
            "type": "object",
            "properties": {},
            "additionalProperties": True,
        }
    )

    @field_validator("args_schema")
    @classmethod
    def validate_args_schema(cls, value: dict[str, Any]) -> dict[str, Any]:
        try:
            Draft202012Validator.check_schema(value)
        except SchemaError as exc:
            raise ValueError(f"invalid JSON schema: {exc.message}") from exc
        return value


class ToolServerSpec(StrictModel):
    name: str = Field(min_length=1)
    tools: list[ToolSpec] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_unique_tool_names(self) -> ToolServerSpec:
        names = [tool.name for tool in self.tools]
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            raise ValueError(
                f"duplicate tool names in server {self.name}: {', '.join(duplicates)}"
            )
        return self


class SinkCapability(StrictModel):
    tool: str = Field(min_length=1)
    payload_fields: list[str] = Field(default_factory=list)
    source_resource_fields: list[str] = Field(default_factory=list)
    match_fields: list[str] = Field(default_factory=list)
    destination_kinds: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_payload_source(self) -> SinkCapability:
        if not self.payload_fields and not self.source_resource_fields:
            raise ValueError(
                "sink capability must define payload_fields or source_resource_fields"
            )
        return self


class ToolInterface(StrictModel):
    servers: list[ToolServerSpec] = Field(default_factory=list)
    sink_capabilities: list[SinkCapability] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_unique_servers(self) -> ToolInterface:
        server_names = [server.name for server in self.servers]
        duplicate_servers = sorted(
            {name for name in server_names if server_names.count(name) > 1}
        )
        if duplicate_servers:
            raise ValueError(
                f"duplicate tool interface servers: {', '.join(duplicate_servers)}"
            )
        known_tools = self.qualified_tool_names
        capability_tools = [capability.tool for capability in self.sink_capabilities]
        duplicate_capabilities = sorted(
            {tool for tool in capability_tools if capability_tools.count(tool) > 1}
        )
        if duplicate_capabilities:
            raise ValueError(
                "duplicate sink capabilities: " + ", ".join(duplicate_capabilities)
            )
        unknown_capabilities = sorted(set(capability_tools) - known_tools)
        if unknown_capabilities:
            raise ValueError(
                "sink capabilities reference unknown tools: "
                + ", ".join(unknown_capabilities)
            )
        return self

    @property
    def qualified_tool_names(self) -> set[str]:
        return {
            f"{server.name}.{tool.name}"
            for server in self.servers
            for tool in server.tools
        }

    def find_tool(self, qualified_tool_name: str) -> tuple[ToolServerSpec, ToolSpec]:
        server_name, tool_name = split_qualified_tool_name(qualified_tool_name)
        for server in self.servers:
            if server.name != server_name:
                continue
            for tool in server.tools:
                if tool.name == tool_name:
                    return server, tool
        raise KeyError(f"unknown tool: {qualified_tool_name}")

    def find_sink_capability(self, qualified_tool_name: str) -> SinkCapability | None:
        for capability in self.sink_capabilities:
            if capability.tool == qualified_tool_name:
                return capability
        return None

    def find_server(self, server_name: str) -> ToolServerSpec:
        for server in self.servers:
            if server.name == server_name:
                return server
        raise KeyError(f"unknown tool server: {server_name}")


def split_qualified_tool_name(tool_name: str) -> tuple[str, str]:
    if "." not in tool_name:
        raise ValueError(f"tool name must be qualified as server.tool: {tool_name}")
    server_name, bare_tool_name = tool_name.split(".", 1)
    if not server_name or not bare_tool_name:
        raise ValueError(f"tool name must be qualified as server.tool: {tool_name}")
    return server_name, bare_tool_name
