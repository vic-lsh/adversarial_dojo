from __future__ import annotations

from adversarial_dojo.agents.agentshim import generate_red_team_submission
from adversarial_dojo.agents.trajectories import AgentTrajectoryRecorder
from adversarial_dojo.config import AgentConfig


def test_recorder_accepts_generic_codex_mcp_tool_call() -> None:
    recorder = AgentTrajectoryRecorder("red_team")

    recorder.on_tool_call(
        "mcp_tool_call",
        {
            "server": "adversarial_dojo_submission",
            "tool": "submit_scenario_proposal",
            "arguments": {"task": {"user_task": "x", "red_team_task": "y"}},
        },
    )

    assert recorder.tool_events[0].tool == (
        "adversarial_dojo_submission.submit_scenario_proposal"
    )
    assert recorder.tool_events[0].arguments == {
        "task": {"user_task": "x", "red_team_task": "y"}
    }


def test_recorder_preserves_unknown_tool_events_without_crashing() -> None:
    recorder = AgentTrajectoryRecorder("red_team")

    recorder.on_tool_call("mcp_tool_call", {"unexpected": "shape"})

    assert recorder.tool_events[0].tool == "mcp_tool_call"
    assert recorder.tool_events[0].arguments == {"unexpected": "shape"}


def test_red_team_submission_validation_feedback_reuses_session(tmp_path) -> None:
    invalid_payload = {"task": {"user_task": "bad", "red_team_task": "bad"}}
    valid_payload = {"task": {"user_task": "ok", "red_team_task": "ok"}}
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
        validator=lambda text: None if "user_task: ok" in text else "missing ok marker",
    )

    assert "user_task: ok" in result
    assert len(RecordingCodingAgent.instances) == 1
    session = RecordingCodingAgent.instances[0].session
    assert session is not None
    assert len(session.prompts) == 2
    assert "missing ok marker" in session.prompts[1]
    rounds = (tmp_path / "scenario_validation_rounds.jsonl").read_text(encoding="utf-8")
    assert '"status": "invalid"' in rounds
    assert '"status": "valid"' in rounds


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

    def start_session(self, cwd=None, silent=True):
        del cwd, silent
        self.session = RecordingSession(self)
        return self.session


class RecordingSession:
    def __init__(self, agent: RecordingCodingAgent) -> None:
        self.agent = agent
        self.prompts: list[str] = []

    def generate(self, prompt, cwd=None, silent=True):
        del cwd, silent
        index = len(self.prompts)
        self.prompts.append(prompt)
        if index < len(self.agent.responses):
            self.agent.event_handler.on_tool_call(
                "adversarial_dojo_submission.submit_scenario_proposal",
                self.agent.responses[index],
            )
        return f"turn {index}"
