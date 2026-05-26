from __future__ import annotations

import argparse
import anyio
from pathlib import Path

from mcp import types
from mcp.server import Server
from mcp.server.stdio import stdio_server

from adversarial_dojo.runtime import ScenarioRuntime
from adversarial_dojo.scenario import Scenario


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--calls", required=True)
    parser.add_argument("--events", required=False, default=None)
    args = parser.parse_args()
    anyio.run(
        run_server,
        args.scenario,
        args.server,
        args.state,
        args.calls,
        args.events,
    )


async def run_server(
    scenario_path: str,
    server_name: str,
    state_path: str,
    calls_path: str,
    events_path: str | None = None,
) -> None:
    scenario = Scenario.model_validate_json(Path(scenario_path).read_text(encoding="utf-8"))
    server_spec = scenario.tool_interface.find_server(server_name)
    mcp_server = Server(server_spec.name)
    calls = Path(calls_path)
    calls.parent.mkdir(parents=True, exist_ok=True)

    @mcp_server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name=tool.name,
                description=tool.description,
                inputSchema=tool.args_schema,
            )
            for tool in server_spec.tools
        ]

    @mcp_server.call_tool(validate_input=True)
    async def call_tool(name: str, arguments: dict) -> types.CallToolResult:
        qualified_tool = f"{server_spec.name}.{name}"
        runtime = ScenarioRuntime.from_state_file(
            scenario,
            state_path=state_path,
            events_path=events_path,
        )
        call = runtime.invoke(qualified_tool, arguments)
        runtime.write_state_file(state_path)
        with calls.open("a", encoding="utf-8") as handle:
            handle.write(call.model_dump_json() + "\n")
        content = []
        if call.result_content:
            content.append(types.TextContent(type="text", text=call.result_content))
        return types.CallToolResult(
            content=content,
            structuredContent=call.structured_content,
            isError=call.is_error,
        )

    async with stdio_server() as (read_stream, write_stream):
        await mcp_server.run(
            read_stream,
            write_stream,
            mcp_server.create_initialization_options(),
        )


if __name__ == "__main__":
    main()
