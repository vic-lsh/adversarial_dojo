from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from adversarial_dojo.agents.utils import normalize_tool_name
from adversarial_dojo.records import ToolCallRecord


class AgentTrajectoryRecorder:
    def __init__(self, role: str, output_dir: Path | None = None) -> None:
        self.role = role
        self.tool_events: list[ToolCallRecord] = []
        self.events_path = output_dir / f"{role}_events.jsonl" if output_dir is not None else None
        self.stream_path = output_dir / f"{role}_stream.txt" if output_dir is not None else None
        if output_dir is not None:
            output_dir.mkdir(parents=True, exist_ok=True)
            self.events_path.write_text("", encoding="utf-8")
            self.stream_path.write_text("", encoding="utf-8")

    def on_thinking(self, text: str) -> None:
        self._write_event("thinking", {"text": text})
        self._append_stream(text)

    def on_tool_call(self, tool: str, args: dict[str, Any] | str | None = None) -> None:
        parsed_args = _parse_tool_args(args)
        recorded_tool, recorded_args = _recorded_tool_call(tool, parsed_args)
        self.tool_events.append(ToolCallRecord(tool=recorded_tool, arguments=recorded_args))
        self._write_event("tool_call", {"tool": recorded_tool, "arguments": recorded_args})

    def on_tool_result(
        self,
        tool: str,
        stdout: str = "",
        stderr: str = "",
        exit_code: int | None = None,
        duration: float | None = None,
    ) -> None:
        self._write_event(
            "tool_result",
            {
                "tool": tool,
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": exit_code,
                "duration": duration,
            },
        )

    def on_usage(self, usage: dict[str, Any]) -> None:
        self._write_event("usage", {"usage": usage})

    def _write_event(self, event_type: str, payload: dict[str, Any]) -> None:
        if self.events_path is None:
            return
        event = {
            "timestamp": time.time(),
            "role": self.role,
            "event": event_type,
            **payload,
        }
        with self.events_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event) + "\n")
            handle.flush()

    def _append_stream(self, text: str) -> None:
        if self.stream_path is None or not text:
            return
        with self.stream_path.open("a", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()


def write_fake_trajectory(role: str, output_dir: Path | None, text: str) -> None:
    if output_dir is None:
        return
    recorder = AgentTrajectoryRecorder(role, output_dir)
    recorder.on_thinking(text)
    recorder.on_usage({"provider": "fake"})


def _parse_tool_args(args: dict[str, Any] | str | None) -> dict[str, Any]:
    if isinstance(args, dict):
        return args
    if isinstance(args, str):
        try:
            loaded = json.loads(args)
        except json.JSONDecodeError:
            return {"raw": args}
        if isinstance(loaded, dict):
            return loaded
        return {"raw": loaded}
    return {}


def _recorded_tool_call(tool: str, args: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    try:
        return normalize_tool_name(tool), args
    except ValueError:
        pass

    if tool == "mcp_tool_call":
        mcp_tool = _mcp_tool_name(args)
        mcp_args = _mcp_call_args(args)
        if mcp_tool is not None:
            try:
                return normalize_tool_name(mcp_tool), mcp_args
            except ValueError:
                return mcp_tool, mcp_args

    return tool, args


def _mcp_tool_name(args: dict[str, Any]) -> str | None:
    server = _string_value(args, "server_name") or _string_value(args, "server")
    name = (
        _string_value(args, "tool_name")
        or _string_value(args, "tool")
        or _string_value(args, "name")
    )
    if name is None:
        return None
    if server is not None and "." not in name and "__" not in name:
        return f"{server}.{name}"
    return name


def _mcp_call_args(args: dict[str, Any]) -> dict[str, Any]:
    for key in ("arguments", "args", "input"):
        value = args.get(key)
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            parsed = _parse_tool_args(value)
            if "raw" not in parsed:
                return parsed
    return args


def _string_value(args: dict[str, Any], key: str) -> str | None:
    value = args.get(key)
    return value if isinstance(value, str) and value else None
