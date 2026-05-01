from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adversarial_dojo.models import MockEnvironment, MockMcpServer, ToolCallRecord


class ToolInvocationRecorder:
    def __init__(self, log_path: str | Path | None = None) -> None:
        self.log_path = Path(log_path) if log_path is not None else None
        self.calls: list[ToolCallRecord] = []
        if self.log_path is not None:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, call: ToolCallRecord) -> None:
        self.calls.append(call)
        if self.log_path is None:
            return
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(call.model_dump_json() + "\n")


class MockToolExecutor:
    def __init__(self, environment: MockEnvironment, recorder: ToolInvocationRecorder | None = None) -> None:
        self.environment = environment
        self.recorder = recorder or ToolInvocationRecorder()
        self._call_counts: dict[str, int] = {}

    def invoke(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        server_name: str | None = None,
    ) -> ToolCallRecord:
        arguments = arguments or {}
        server, tool = self.environment.find_tool(server_name, tool_name)
        key = f"{server.name}.{tool.name}"
        call_index = self._call_counts.get(key, 0)
        self._call_counts[key] = call_index + 1
        response = tool.select_response(arguments, call_index=call_index)
        call = ToolCallRecord(
            server_name=server.name,
            tool_name=tool.name,
            arguments=arguments,
            result_content=response.content,
            structured_content=response.structured_content,
            is_error=response.is_error,
        )
        self.recorder.record(call)
        return call


def load_jsonl_calls(path: str | Path) -> list[ToolCallRecord]:
    call_path = Path(path)
    if not call_path.exists():
        return []
    calls: list[ToolCallRecord] = []
    with call_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                calls.append(ToolCallRecord.model_validate(json.loads(line)))
    return calls


def server_to_environment(server: MockMcpServer) -> MockEnvironment:
    return MockEnvironment(mcp_servers=[server])
