from __future__ import annotations

import ast
import signal
import textwrap
import threading
from collections.abc import Callable
from contextlib import contextmanager
from types import FrameType
from typing import Any

from adversarial_dojo.scenario import ToolImplSpec, ToolResult


class ToolImplValidationError(ValueError):
    pass


class ToolImplTimeout(RuntimeError):
    pass


class ToolImplExecutor:
    def __init__(self, impls: list[ToolImplSpec], *, timeout_seconds: float) -> None:
        self.timeout_seconds = timeout_seconds
        self._functions = {
            impl.tool: _compile_tool_impl(impl)
            for impl in impls
        }

    def invoke(self, tool: str, args: dict[str, Any], state: Any) -> ToolResult:
        function = self._functions.get(tool)
        if function is None:
            return ToolResult(content=f"tool {tool} is not implemented", is_error=True)
        with _time_limit(self.timeout_seconds):
            raw = function(args, state, ToolResult)
        if isinstance(raw, ToolResult):
            return raw
        if isinstance(raw, dict):
            return ToolResult.model_validate(raw)
        raise TypeError(f"tool impl {tool} returned unsupported result type: {type(raw).__name__}")

    def generated_source(self) -> str:
        chunks = []
        for tool, function in sorted(self._functions.items()):
            body = getattr(function, "__source_body__", "")
            function_name = _function_name(tool)
            chunks.append(
                f"def {function_name}(args, state, ToolResult):\n"
                f"{textwrap.indent(body, '    ')}\n"
            )
        return "\n".join(chunks)


def validate_tool_impl_body(body: str) -> None:
    if not body.strip():
        raise ToolImplValidationError("tool impl body must not be empty")
    try:
        tree = ast.parse(body, mode="exec")
    except SyntaxError as exc:
        raise ToolImplValidationError(f"invalid tool impl syntax: {exc.msg}") from exc
    for node in ast.walk(tree):
        if isinstance(node, _BLOCKED_NODES):
            raise ToolImplValidationError(
                f"unsupported tool impl syntax: {type(node).__name__}"
            )
        if isinstance(node, ast.Name) and node.id in _BLOCKED_NAMES:
            raise ToolImplValidationError(f"blocked name in tool impl: {node.id}")
        if isinstance(node, ast.Attribute) and node.attr.startswith("_"):
            raise ToolImplValidationError(
                f"blocked private attribute access in tool impl: {node.attr}"
            )
        if isinstance(node, ast.Call):
            callee = node.func
            if isinstance(callee, ast.Name) and callee.id in _BLOCKED_CALLS:
                raise ToolImplValidationError(f"blocked call in tool impl: {callee.id}")


def _compile_tool_impl(impl: ToolImplSpec) -> Callable[[dict[str, Any], Any, type[ToolResult]], ToolResult]:
    validate_tool_impl_body(impl.body)
    source = (
        "def __tool_impl__(args, state, ToolResult):\n"
        + textwrap.indent(impl.body.rstrip() + "\n", "    ")
    )
    namespace: dict[str, Any] = {"__builtins__": _SAFE_BUILTINS}
    exec(compile(source, filename=f"<tool_impl:{impl.tool}>", mode="exec"), namespace)
    function = namespace["__tool_impl__"]
    function.__source_body__ = impl.body.rstrip() + "\n"
    return function


@contextmanager
def _time_limit(seconds: float):
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def handle_timeout(signum: int, frame: FrameType | None) -> None:
        del signum, frame
        raise ToolImplTimeout(f"tool impl exceeded {seconds:.2f}s timeout")

    previous_handler = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, handle_timeout)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)


def _function_name(tool: str) -> str:
    return "impl_" + "".join(char if char.isalnum() else "_" for char in tool)


_BLOCKED_NODES = (
    ast.AsyncFunctionDef,
    ast.AsyncFor,
    ast.AsyncWith,
    ast.Await,
    ast.ClassDef,
    ast.Delete,
    ast.FunctionDef,
    ast.Global,
    ast.Import,
    ast.ImportFrom,
    ast.Lambda,
    ast.Nonlocal,
    ast.Try,
    ast.With,
    ast.Yield,
    ast.YieldFrom,
)

_BLOCKED_NAMES = {
    "__builtins__",
    "__import__",
    "breakpoint",
    "compile",
    "eval",
    "exec",
    "globals",
    "input",
    "locals",
    "open",
}

_BLOCKED_CALLS = _BLOCKED_NAMES | {
    "dir",
    "getattr",
    "setattr",
    "delattr",
    "help",
    "memoryview",
    "super",
    "vars",
}

_SAFE_BUILTINS = {
    "all": all,
    "any": any,
    "bool": bool,
    "dict": dict,
    "enumerate": enumerate,
    "float": float,
    "int": int,
    "len": len,
    "list": list,
    "max": max,
    "min": min,
    "range": range,
    "set": set,
    "sorted": sorted,
    "str": str,
    "sum": sum,
    "tuple": tuple,
}
