from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path
from typing import Any

from adversarial_dojo.agents.constants import REPO_ROOT
from adversarial_dojo.config import AgentConfig
from adversarial_dojo.tool_interfaces.models import split_qualified_tool_name


def configured_tool_name(configured_call: dict[str, Any]) -> str:
    if "tool" in configured_call:
        return normalize_tool_name(str(configured_call["tool"]))
    if "tool_name" in configured_call and "server_name" in configured_call:
        return f"{configured_call['server_name']}.{configured_call['tool_name']}"
    return normalize_tool_name(str(configured_call["tool_name"]))


def parse_prompt_tool_directives(prompt: str) -> list[tuple[str, dict[str, Any]]]:
    pattern = re.compile(r"\[\[call_tool\s+([A-Za-z0-9_.-]+)(?:\s+({.*?}))?\]\]", re.DOTALL)
    calls: list[tuple[str, dict[str, Any]]] = []
    for match in pattern.finditer(prompt):
        raw_name = match.group(1)
        raw_args = match.group(2)
        args: dict[str, Any] = {}
        if raw_args:
            loaded = json.loads(raw_args)
            if isinstance(loaded, dict):
                args = loaded
        calls.append((normalize_tool_name(raw_name), args))
    return calls


def normalize_tool_name(raw_tool: str) -> str:
    if raw_tool.startswith("mcp__"):
        parts = raw_tool.split("__", 2)
        if len(parts) == 3:
            return f"{parts[1]}.{parts[2]}"
    if "." in raw_tool:
        split_qualified_tool_name(raw_tool)
        return raw_tool
    if "__" in raw_tool:
        server_name, tool_name = raw_tool.split("__", 1)
        return f"{server_name}.{tool_name}"
    raise ValueError(f"tool name must be qualified as server.tool: {raw_tool}")


def runtime_events_path(output_dir: Path | None) -> Path | None:
    return output_dir / "runtime_events.jsonl" if output_dir is not None else None


def make_coding_agent(coding_agent_cls, config: AgentConfig, **kwargs):
    agent = coding_agent_cls(
        provider=config.provider,
        model=config.model,
        backend_kwargs=config.backend_kwargs,
        **kwargs,
    )
    if config.provider == "codex" and config.reasoning_effort:
        inject_codex_reasoning_effort(agent, config.reasoning_effort)
    return agent


def generate_in_session(agent, prompt: str) -> str:
    session = getattr(agent, "_adversarial_dojo_session", None)
    if session is None and hasattr(agent, "start_session"):
        try:
            session = agent.start_session(cwd=".", silent=True)
        except (AttributeError, NotImplementedError):
            session = None
        else:
            setattr(agent, "_adversarial_dojo_session", session)
    if session is not None:
        return session.generate(prompt, cwd=".", silent=True)
    return agent.generate(prompt, cwd=".", silent=True)


def inject_codex_reasoning_effort(agent, reasoning_effort: str) -> None:
    backend = getattr(agent, "backend", agent)
    original_get_command = backend._get_command

    def get_command_with_reasoning(*args, **kwargs):
        cmd = original_get_command(*args, **kwargs)
        if "--model" in cmd:
            insert_at = cmd.index("--model")
        elif "-" in cmd:
            insert_at = cmd.index("-")
        else:
            insert_at = len(cmd)
        return cmd[:insert_at] + ["-c", f'model_reasoning_effort="{reasoning_effort}"'] + cmd[insert_at:]

    backend._get_command = get_command_with_reasoning


def prepare_victim_workspace(output_dir: Path | None, attempt: int) -> Path:
    victim_tmp = tempfile.mkdtemp(prefix=f"workspace-{attempt:03d}-")
    victim_cwd = Path(victim_tmp)
    write_victim_workspace_hint(output_dir, victim_cwd)
    return victim_cwd


def write_victim_workspace_hint(output_dir: Path | None, victim_cwd: Path) -> None:
    if output_dir is None:
        return
    (output_dir / "victim_workspace.txt").write_text(f"{victim_cwd}\n", encoding="utf-8")


def victim_sandbox_config(victim_cwd: Path):
    from agentshim.sandbox import SandboxConfig

    return SandboxConfig(
        allow_read=[str(victim_cwd)],
        allow_write=[str(victim_cwd)],
        deny_read=[str(REPO_ROOT)],
        deny_write=[str(REPO_ROOT)],
        confine_native_reads_to=[str(victim_cwd)],
    )
