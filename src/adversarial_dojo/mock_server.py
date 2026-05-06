from __future__ import annotations

import argparse
import anyio
from mcp import types
from mcp.server import Server
from mcp.server.stdio import stdio_server

from adversarial_dojo.models import MockMcpServer
from adversarial_dojo.mock_tools import MockToolExecutor, ToolInvocationRecorder, server_to_environment


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--calls", required=True)
    parser.add_argument("--state", required=False, default=None)
    args = parser.parse_args()
    anyio.run(run_server, args.server, args.calls, args.state)


async def run_server(server_path: str, calls_path: str, state_path: str | None = None) -> None:
    with open(server_path, "r", encoding="utf-8") as handle:
        mock_server = MockMcpServer.model_validate_json(handle.read())
    mcp_server = Server(mock_server.name)
    executor = MockToolExecutor(
        server_to_environment(mock_server),
        recorder=ToolInvocationRecorder(calls_path),
        state_path=state_path,
    )

    @mcp_server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [
            types.Tool(name=tool.name, description=tool.description, inputSchema=tool.args_schema)
            for tool in mock_server.tools
        ]

    @mcp_server.call_tool(validate_input=True)
    async def call_tool(name: str, arguments: dict) -> types.CallToolResult:
        call = executor.invoke(tool_name=name, server_name=mock_server.name, arguments=arguments)
        content = []
        if call.result_content:
            content.append(types.TextContent(type="text", text=call.result_content))
        return types.CallToolResult(
            content=content,
            structuredContent=call.structured_content,
            isError=call.is_error,
        )

    async with stdio_server() as (read_stream, write_stream):
        await mcp_server.run(read_stream, write_stream, mcp_server.create_initialization_options())


if __name__ == "__main__":
    main()
