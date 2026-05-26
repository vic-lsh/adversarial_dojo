from __future__ import annotations

import pytest

from adversarial_dojo.runtime import ResourceStore
from adversarial_dojo.runtime.tool_impl import (
    ToolImplExecutor,
    ToolImplTimeout,
    ToolImplValidationError,
    validate_tool_impl_body,
)
from adversarial_dojo.scenario import ToolImplSpec


@pytest.mark.parametrize(
    "body, message",
    [
        ("import os\nreturn ToolResult(content='x')", "Import"),
        ("global cache\ncache = 1\nreturn ToolResult(content='x')", "Global"),
        ("def helper():\n    return 'x'\nreturn ToolResult(content=helper())", "FunctionDef"),
        ("return ToolResult(content=open('/tmp/x').read())", "open"),
        ("return ToolResult(content=eval('1 + 1'))", "eval"),
        ("return ToolResult(content=args.__class__.__name__)", "private attribute"),
        ("return ToolResult(content=getattr(args, 'keys')())", "getattr"),
    ],
)
def test_tool_impl_static_validation_blocks_unsafe_constructs(
    body: str,
    message: str,
) -> None:
    with pytest.raises(ToolImplValidationError, match=message):
        validate_tool_impl_body(body)


def test_tool_impl_executor_accepts_dict_return_shape() -> None:
    executor = ToolImplExecutor(
        [ToolImplSpec(tool="docs.read_note", body="return {'content': args['text']}")],
        timeout_seconds=1.0,
    )

    result = executor.invoke("docs.read_note", {"text": "ok"}, ResourceStore([]))

    assert result.content == "ok"
    assert result.is_error is False


def test_tool_impl_executor_times_out_busy_loop() -> None:
    executor = ToolImplExecutor(
        [ToolImplSpec(tool="docs.read_note", body="while True:\n    pass")],
        timeout_seconds=0.01,
    )

    with pytest.raises(ToolImplTimeout):
        executor.invoke("docs.read_note", {}, ResourceStore([]))
