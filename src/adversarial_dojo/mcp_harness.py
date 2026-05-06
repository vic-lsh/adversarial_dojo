from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from adversarial_dojo.models import MockEnvironment
from adversarial_dojo.mock_tools import load_jsonl_calls


class MockMcpHarness:
    def __init__(self, environment: MockEnvironment, output_dir: Path | None, attempt: int) -> None:
        self.environment = environment
        self.output_dir = output_dir
        self.attempt = attempt
        self._tmp: tempfile.TemporaryDirectory[str] | None = None
        self._root: Path | None = None
        self._call_logs: list[Path] = []
        self._state_path: Path | None = None
        self.mcp_servers = []

    def __enter__(self) -> MockMcpHarness:
        from agentshim import StdioMcpServer

        if self.output_dir is not None:
            root = self.output_dir / "mcp" / f"attempt-{self.attempt}"
            root.mkdir(parents=True, exist_ok=True)
            root = root.resolve()
        else:
            self._tmp = tempfile.TemporaryDirectory(prefix="adversarial-dojo-mcp-")
            root = Path(self._tmp.name)
        self._root = root
        self._state_path = root / "shared_state.json"
        for server in self.environment.mcp_servers:
            spec_path = root / f"{server.name}.json"
            call_log = root / f"{server.name}.calls.jsonl"
            spec_path.write_text(server.model_dump_json(), encoding="utf-8")
            self._call_logs.append(call_log)
            self.mcp_servers.append(
                StdioMcpServer(
                    name=server.name,
                    command=sys.executable,
                    args=[
                        "-m",
                        "adversarial_dojo.mock_server",
                        "--server",
                        str(spec_path),
                        "--calls",
                        str(call_log),
                        "--state",
                        str(self._state_path),
                    ],
                )
            )
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._tmp is not None:
            self._tmp.cleanup()

    def collect_calls(self):
        calls = []
        for call_log in self._call_logs:
            calls.extend(load_jsonl_calls(call_log))
        return calls
