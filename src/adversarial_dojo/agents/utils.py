from __future__ import annotations

import json
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

from adversarial_dojo.agents.constants import REPO_ROOT
from adversarial_dojo.config import AgentConfig, ExperimentConfig
from adversarial_dojo.records import AttemptRecord
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
    if config.provider == "codex":
        configure_codex_execution(agent, config.reasoning_effort)
    return agent


def generate_in_session(
    agent,
    prompt: str,
    *,
    cwd: Path | str = ".",
    timeout_seconds: float | None = None,
) -> str:
    cwd_text = str(cwd)
    timeout = int(timeout_seconds) if timeout_seconds is not None else None
    session = getattr(agent, "_adversarial_dojo_session", None)
    if session is None and hasattr(agent, "start_session"):
        try:
            session = agent.start_session(cwd=cwd_text, timeout=timeout, silent=True)
        except (AttributeError, NotImplementedError):
            session = None
        else:
            setattr(agent, "_adversarial_dojo_session", session)
    if session is not None:
        return session.generate(prompt, cwd=cwd_text, timeout=timeout, silent=True)
    return agent.generate(prompt, cwd=cwd_text, timeout=timeout, silent=True)


def configure_codex_execution(agent, reasoning_effort: str | None = None) -> None:
    backend = getattr(agent, "backend", agent)
    if getattr(backend, "_adversarial_dojo_codex_configured", False):
        return
    env = getattr(backend, "env", None)
    if isinstance(env, dict):
        for key in ("CODEX_THREAD_ID", "CODEX_CI", "CODEX_SANDBOX_NETWORK_DISABLED"):
            env.pop(key, None)
    original_get_command = backend._get_command
    original_create_session = backend._create_session

    def get_command_with_adversarial_dojo_defaults(*args, **kwargs):
        cmd = original_get_command(*args, **kwargs)
        cmd = [arg for arg in cmd if arg != "--dangerously-bypass-approvals-and-sandbox"]
        is_resume = len(cmd) >= 3 and cmd[1:3] == ["exec", "resume"]
        insert_at = cmd.index("-") if "-" in cmd else len(cmd)
        injected: list[str] = []
        if not is_resume and "--sandbox" not in cmd:
            injected.extend(["--sandbox", "workspace-write"])
        for flag in ("--skip-git-repo-check", "--ignore-user-config", "--ignore-rules"):
            if flag not in cmd:
                injected.append(flag)
        if reasoning_effort:
            injected.extend(["-c", f'model_reasoning_effort="{reasoning_effort}"'])
        return cmd[:insert_at] + injected + cmd[insert_at:]

    def create_session_with_workspace_root(cmd, cwd=None, *args, **kwargs):
        adjusted_cmd = list(cmd)
        is_resume = len(adjusted_cmd) >= 3 and adjusted_cmd[1:3] == ["exec", "resume"]
        if cwd is not None and not is_resume and "--cd" not in adjusted_cmd:
            insert_at = adjusted_cmd.index("-") if "-" in adjusted_cmd else len(adjusted_cmd)
            adjusted_cmd = adjusted_cmd[:insert_at] + ["--cd", str(cwd)] + adjusted_cmd[insert_at:]
        return original_create_session(adjusted_cmd, cwd, *args, **kwargs)

    backend._get_command = get_command_with_adversarial_dojo_defaults
    backend._create_session = create_session_with_workspace_root
    backend._adversarial_dojo_codex_configured = True


def inject_codex_reasoning_effort(agent, reasoning_effort: str) -> None:
    configure_codex_execution(agent, reasoning_effort)


def prepare_victim_workspace(output_dir: Path | None, attempt: int) -> Path:
    victim_tmp = tempfile.mkdtemp(prefix=f"workspace-{attempt:03d}-")
    victim_cwd = Path(victim_tmp)
    write_victim_workspace_hint(output_dir, victim_cwd)
    return victim_cwd


def prepare_agent_workspace(
    *,
    role: str,
    config: ExperimentConfig,
    attempt: int,
    output_dir: Path | None,
    previous_attempts: list[AttemptRecord] | None = None,
    attempt_dir: Path | None = None,
) -> Path:
    workspace = Path(tempfile.mkdtemp(prefix=f"{role}-workspace-{attempt:03d}-"))
    _copy_tool_interface_sources(config, workspace)
    if previous_attempts:
        _write_previous_attempts(workspace, previous_attempts)
        _copy_previous_attempt_artifacts(workspace, output_dir, previous_attempts)
    if role == "analyzer" and attempt_dir is not None:
        _copy_artifact_dir(attempt_dir, workspace / "current_attempt")
    write_agent_workspace_hint(output_dir, role, workspace)
    return workspace


def write_agent_workspace_hint(output_dir: Path | None, role: str, workspace: Path) -> None:
    if output_dir is None:
        return
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / f"{role}_workspace.txt").write_text(f"{workspace}\n", encoding="utf-8")


def write_victim_workspace_hint(output_dir: Path | None, victim_cwd: Path) -> None:
    if output_dir is None:
        return
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "victim_workspace.txt").write_text(f"{victim_cwd}\n", encoding="utf-8")


def _copy_tool_interface_sources(config: ExperimentConfig, workspace: Path) -> None:
    for source in config.tool_interface_source_files:
        source_path = Path(source)
        if not source_path.exists():
            continue
        if source_path.suffix.lower() == ".proto":
            target = workspace / "tool_interface.proto"
        elif source_path.suffix.lower() in {".yaml", ".yml"}:
            target = workspace / "tool_interface_sinks.yaml"
        else:
            target = workspace / source_path.name
        shutil.copyfile(source_path, target)


def _write_previous_attempts(workspace: Path, attempts: list[AttemptRecord]) -> None:
    previous_dir = workspace / "previous_attempts"
    previous_dir.mkdir(parents=True, exist_ok=True)
    records = [attempt.model_dump(mode="json") for attempt in attempts]
    (previous_dir / "attempts.json").write_text(
        json.dumps(records, indent=2) + "\n",
        encoding="utf-8",
    )


def _copy_previous_attempt_artifacts(
    workspace: Path,
    output_dir: Path | None,
    attempts: list[AttemptRecord],
) -> None:
    if output_dir is None:
        return
    run_dir = output_dir.parent
    previous_dir = workspace / "previous_attempts"
    for attempt in attempts:
        source = run_dir / f"attempt-{attempt.attempt:03d}"
        if not source.exists():
            continue
        _copy_artifact_dir(source, previous_dir / f"attempt-{attempt.attempt:03d}")


def _copy_artifact_dir(source: Path, target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    allowed_names = {
        "analysis.json",
        "attempt.json",
        "leak_events.json",
        "metadata.json",
        "proposal.json",
        "proposal.yaml",
        "scenario.json",
        "scenario.yaml",
        "tool_calls.json",
        "victim_output.txt",
        "victim_prompt.txt",
    }
    for name in allowed_names:
        source_file = source / name
        if source_file.exists() and source_file.is_file():
            shutil.copyfile(source_file, target / name)


def victim_sandbox_config(victim_cwd: Path):
    from agentshim.sandbox import SandboxConfig

    return SandboxConfig(
        allow_read=[str(victim_cwd)],
        allow_write=[str(victim_cwd)],
        deny_read=[str(REPO_ROOT)],
        deny_write=[str(REPO_ROOT)],
        confine_native_reads_to=[str(victim_cwd)],
    )
