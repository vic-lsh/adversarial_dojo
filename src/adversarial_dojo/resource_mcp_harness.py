from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from adversarial_dojo.records import LeakEvent, ToolCallRecord
from adversarial_dojo.scenario import Scenario


class ResourceMcpHarness:
    def __init__(
        self,
        scenario: Scenario,
        output_dir: Path | None,
        attempt: int,
        run_name: str | None = None,
    ) -> None:
        self.scenario = scenario
        self.output_dir = output_dir
        self.attempt = attempt
        self.run_name = run_name or f"attempt-{attempt}"
        self._tmp: tempfile.TemporaryDirectory[str] | None = None
        self._root: Path | None = None
        self._call_logs: list[Path] = []
        self._state_path: Path | None = None
        self._events_path: Path | None = None
        self.mcp_servers = []

    def __enter__(self) -> ResourceMcpHarness:
        from agentshim import StdioMcpServer

        if self.output_dir is not None:
            root = self.output_dir / "mcp" / self.run_name
            root.mkdir(parents=True, exist_ok=True)
            root = root.resolve()
        else:
            self._tmp = tempfile.TemporaryDirectory(prefix="adversarial-dojo-mcp-")
            root = Path(self._tmp.name)
        self._root = root
        scenario_path = root / "scenario.json"
        self._state_path = root / "runtime_state.json"
        self._events_path = root / "runtime_events.jsonl"
        scenario_path.write_text(self.scenario.model_dump_json(), encoding="utf-8")
        self._state_path.write_text(
            json.dumps(
                {
                    "resources": [
                        resource.model_dump(mode="json")
                        for resource in self.scenario.resources
                    ],
                    "observed_canaries": [],
                    "leak_events": [],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        for server in self.scenario.tool_interface.servers:
            call_log = root / f"{server.name}.calls.jsonl"
            self._call_logs.append(call_log)
            self.mcp_servers.append(
                StdioMcpServer(
                    name=server.name,
                    command=sys.executable,
                    args=[
                        "-m",
                        "adversarial_dojo.resource_mcp_server",
                        "--scenario",
                        str(scenario_path),
                        "--server",
                        server.name,
                        "--state",
                        str(self._state_path),
                        "--calls",
                        str(call_log),
                        "--events",
                        str(self._events_path),
                    ],
                )
            )
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._tmp is not None:
            self._tmp.cleanup()

    def collect_calls(self) -> list[ToolCallRecord]:
        calls: list[ToolCallRecord] = []
        for call_log in self._call_logs:
            calls.extend(_load_jsonl_calls(call_log))
        return calls

    def collect_leaks(self) -> list[LeakEvent]:
        if self._state_path is None or not self._state_path.exists():
            return []
        state = json.loads(self._state_path.read_text(encoding="utf-8"))
        return [
            LeakEvent.model_validate(item)
            for item in state.get("leak_events", [])
        ]

    def final_resource_state(self) -> list[dict]:
        if self._state_path is None or not self._state_path.exists():
            return []
        state = json.loads(self._state_path.read_text(encoding="utf-8"))
        return list(state.get("resources", []))


def _load_jsonl_calls(path: Path) -> list[ToolCallRecord]:
    if not path.exists():
        return []
    calls: list[ToolCallRecord] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            calls.append(ToolCallRecord.model_validate_json(line))
    return calls
