from __future__ import annotations

import time

from adversarial_dojo.agents.agentshim import generate_red_team_submission
from adversarial_dojo.agents.constants import AGENT_TURN_TIMEOUT_SECONDS
from adversarial_dojo.agents.trajectories import AgentTrajectoryRecorder
from adversarial_dojo.agents.utils import configure_codex_execution, prepare_agent_workspace
from adversarial_dojo.config import AgentConfig
from adversarial_dojo.config import ExperimentConfig
from adversarial_dojo.records import AttemptRecord
from adversarial_dojo.red_team_submission import RedTeamSubmissionHarness


def test_recorder_accepts_generic_codex_mcp_tool_call() -> None:
    recorder = AgentTrajectoryRecorder("red_team")

    recorder.on_tool_call(
        "mcp_tool_call",
        {
            "server": "adversarial_dojo_submission",
            "tool": "submit_scenario_proposal",
            "arguments": {"red_team_task": "y"},
        },
    )

    assert recorder.tool_events[0].tool == (
        "adversarial_dojo_submission.submit_scenario_proposal"
    )
    assert recorder.tool_events[0].arguments == {"red_team_task": "y"}


def test_recorder_preserves_unknown_tool_events_without_crashing() -> None:
    recorder = AgentTrajectoryRecorder("red_team")

    recorder.on_tool_call("mcp_tool_call", {"unexpected": "shape"})

    assert recorder.tool_events[0].tool == "mcp_tool_call"
    assert recorder.tool_events[0].arguments == {"unexpected": "shape"}


def test_recorder_preserves_prior_events_across_retry_instances(tmp_path) -> None:
    AgentTrajectoryRecorder._initialized_paths.clear()
    first = AgentTrajectoryRecorder("red_team", tmp_path)
    first.on_thinking("first turn\n")

    second = AgentTrajectoryRecorder("red_team", tmp_path)
    second.on_thinking("retry turn\n")

    events = (tmp_path / "red_team_events.jsonl").read_text(encoding="utf-8")
    stream = (tmp_path / "red_team_stream.txt").read_text(encoding="utf-8")
    assert "first turn" in events
    assert "retry turn" in events
    assert stream == "first turn\nretry turn\n"


def test_red_team_submission_validation_feedback_reuses_session(tmp_path) -> None:
    invalid_payload = {"red_team_task": "bad"}
    valid_payload = {"red_team_task": "ok"}
    RecordingCodingAgent.instances = []

    result = generate_red_team_submission(
        RecordingCodingAgent,
        AgentConfig(
            provider="fake",
            backend_kwargs={"responses": [invalid_payload, valid_payload]},
        ),
        prompt="submit a scenario",
        kind="scenario",
        attempt=1,
        output_dir=tmp_path,
        event_recorder=AgentTrajectoryRecorder("red_team", tmp_path),
        validator=lambda text: None if "red_team_task: ok" in text else "missing ok marker",
        cwd=tmp_path / "agent-workspace",
    )

    assert "red_team_task: ok" in result
    assert len(RecordingCodingAgent.instances) == 1
    session = RecordingCodingAgent.instances[0].session
    assert session is not None
    assert len(session.prompts) == 2
    assert session.start_cwd == str(tmp_path / "agent-workspace")
    assert session.start_timeout == AGENT_TURN_TIMEOUT_SECONDS
    assert session.generate_cwds == [
        str(tmp_path / "agent-workspace"),
        str(tmp_path / "agent-workspace"),
    ]
    assert session.generate_timeouts == [
        AGENT_TURN_TIMEOUT_SECONDS,
        AGENT_TURN_TIMEOUT_SECONDS,
    ]
    assert "missing ok marker" in session.prompts[1]
    rounds = (tmp_path / "scenario_validation_rounds.jsonl").read_text(encoding="utf-8")
    assert '"status": "invalid"' in rounds
    assert '"status": "valid"' in rounds


def test_submission_mcp_artifacts_are_separated_by_kind(tmp_path) -> None:
    with RedTeamSubmissionHarness("user_task", output_dir=tmp_path, attempt=1) as user:
        user_root = user._harness._root
    with RedTeamSubmissionHarness("scenario", output_dir=tmp_path, attempt=1) as scenario:
        scenario_root = scenario._harness._root

    assert user_root == tmp_path / "mcp" / "user_task-attempt-1"
    assert scenario_root == tmp_path / "mcp" / "scenario-attempt-1"
    assert user_root != scenario_root


def test_submission_generation_times_out_without_tool_call(tmp_path) -> None:
    SlowCodingAgent.instances = []

    try:
        generate_red_team_submission(
            SlowCodingAgent,
            AgentConfig(provider="fake"),
            prompt="submit a scenario",
            kind="scenario",
            attempt=1,
            output_dir=tmp_path,
            event_recorder=AgentTrajectoryRecorder("red_team", tmp_path),
            turn_timeout_seconds=0.01,
        )
    except TimeoutError as exc:
        assert "agent turn exceeded" in str(exc)
    else:
        raise AssertionError("expected agent turn timeout")


def test_prepare_agent_workspace_copies_interface_sources_and_previous_attempts(
    tmp_path,
) -> None:
    config = ExperimentConfig.from_toml_file("examples/fake_open_search.toml")
    run_dir = tmp_path / "run"
    (run_dir / "attempt-002").mkdir(parents=True)
    previous_attempt_dir = run_dir / "attempt-001"
    previous_attempt_dir.mkdir(parents=True)
    (previous_attempt_dir / "attempt.json").write_text('{"attempt": 1}\n', encoding="utf-8")
    (previous_attempt_dir / "generated_tool_code.py").write_text(
        "should not be copied\n",
        encoding="utf-8",
    )

    workspace = prepare_agent_workspace(
        role="red_team",
        config=config,
        attempt=2,
        output_dir=run_dir / "attempt-002",
        previous_attempts=[AttemptRecord(attempt=1, error="failed")],
    )

    assert (workspace / "tool_interface_sinks.yaml").exists()
    assert (workspace / "tool_interface.proto").exists()
    assert (workspace / "previous_attempts" / "attempts.json").exists()
    assert (workspace / "previous_attempts" / "attempt-001" / "attempt.json").exists()
    assert not (
        workspace / "previous_attempts" / "attempt-001" / "generated_tool_code.py"
    ).exists()
    assert (run_dir / "attempt-002" / "red_team_workspace.txt").read_text(
        encoding="utf-8"
    ).strip() == str(workspace)


def test_codex_command_uses_workspace_root_and_sandbox(tmp_path) -> None:
    agent = FakeCodexAgent()

    configure_codex_execution(agent, "high")

    cmd = agent._get_command("prompt")
    session = agent._create_session(cmd, tmp_path, 123, True)

    assert "--dangerously-bypass-approvals-and-sandbox" not in cmd
    assert "--sandbox" in cmd
    assert cmd[cmd.index("--sandbox") + 1] == "workspace-write"
    assert "--skip-git-repo-check" in cmd
    assert "--ephemeral" in cmd
    assert "--ignore-rules" in cmd
    assert f'model_reasoning_effort="high"' in cmd
    assert "--cd" in session.cmd
    assert session.cmd[session.cmd.index("--cd") + 1] == str(tmp_path)


class RecordingCodingAgent:
    instances = []

    def __init__(
        self,
        provider,
        model=None,
        backend_kwargs=None,
        mcp_servers=None,
        event_handler=None,
        **kwargs,
    ) -> None:
        del provider, model, mcp_servers, kwargs
        self.responses = list((backend_kwargs or {}).get("responses", []))
        self.event_handler = event_handler
        self.session = None
        self.instances.append(self)

    def start_session(self, cwd=None, timeout=None, silent=True):
        del silent
        self.session = RecordingSession(self)
        self.session.start_cwd = cwd
        self.session.start_timeout = timeout
        return self.session


class RecordingSession:
    def __init__(self, agent: RecordingCodingAgent) -> None:
        self.agent = agent
        self.prompts: list[str] = []
        self.start_cwd: str | None = None
        self.start_timeout: int | None = None
        self.generate_cwds: list[str | None] = []
        self.generate_timeouts: list[int | None] = []

    def generate(self, prompt, cwd=None, timeout=None, silent=True):
        del silent
        index = len(self.prompts)
        self.prompts.append(prompt)
        self.generate_cwds.append(cwd)
        self.generate_timeouts.append(timeout)
        if index < len(self.agent.responses):
            self.agent.event_handler.on_tool_call(
                "adversarial_dojo_submission.submit_scenario_proposal",
                self.agent.responses[index],
            )
        return f"turn {index}"


class FakeCodexAgent:
    def _get_command(self, prompt, resume_session_id=None):
        del prompt
        cmd = ["codex", "exec"]
        if resume_session_id:
            cmd.extend(["resume", resume_session_id])
        cmd.extend(["--dangerously-bypass-approvals-and-sandbox", "--json", "-"])
        return cmd

    def _create_session(self, cmd, cwd=None, timeout=300, silent=False, **kwargs):
        del cwd, timeout, silent, kwargs
        return FakeCodexSession(cmd)


class FakeCodexSession:
    def __init__(self, cmd) -> None:
        self.cmd = cmd


class SlowCodingAgent:
    instances = []

    def __init__(
        self,
        provider,
        model=None,
        backend_kwargs=None,
        mcp_servers=None,
        event_handler=None,
        **kwargs,
    ) -> None:
        del provider, model, backend_kwargs, mcp_servers, event_handler, kwargs
        self.instances.append(self)

    def generate(self, prompt, cwd=None, timeout=None, silent=True):
        del prompt, cwd, timeout, silent
        time.sleep(1)
        return "too late"
