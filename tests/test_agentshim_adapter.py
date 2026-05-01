from __future__ import annotations

from adversarial_dojo.agents import AgentshimRunner, _make_coding_agent, _recover_yaml_from_stream, _scenario_generation_prompt
from adversarial_dojo.attacker_submission import SUBMISSION_SERVER_NAME, SUBMIT_PATCH_TOOL, SUBMIT_SCENARIO_TOOL
from adversarial_dojo.models import AgentConfig, AttackScenario, AttemptRecord, ExperimentConfig
from tests.test_models import valid_scenario_data


def test_agentshim_attacker_adapter_wires_provider_model_and_backend_kwargs(monkeypatch) -> None:
    constructed = {}

    class FakeCodingAgent:
        def __init__(self, **kwargs):
            constructed.update(kwargs)
            self.event_handler = kwargs["event_handler"]

        def generate(self, prompt, cwd=None, silent=False):
            assert "AttackPatch" in prompt
            self.event_handler.on_tool_call(
                f"mcp__{SUBMISSION_SERVER_NAME}__{SUBMIT_PATCH_TOOL}",
                {"user_task": "patched"},
            )
            return "submitted"

    import agentshim

    monkeypatch.setattr(agentshim, "CodingAgent", FakeCodingAgent)
    config = AgentConfig(provider="codex", model="gpt-test", backend_kwargs={"x": 1})
    runner = AgentshimRunner(role="attacker", config=config)
    scenario = AttackScenario.model_validate(valid_scenario_data())

    response = runner.propose_patch(scenario, attempt=1, previous_attempts=[])

    assert response == "user_task: patched\n"
    assert constructed["provider"] == "codex"
    assert constructed["model"] == "gpt-test"
    assert constructed["backend_kwargs"] == {"x": 1}
    assert constructed["mcp_servers"][0].name == SUBMISSION_SERVER_NAME


def test_agentshim_attacker_adapter_writes_streaming_trajectory(monkeypatch, tmp_path) -> None:
    class FakeCodingAgent:
        def __init__(self, **kwargs):
            self.event_handler = kwargs["event_handler"]

        def generate(self, prompt, cwd=None, silent=False):
            self.event_handler.on_thinking("drafting scenario\n")
            self.event_handler.on_tool_call(
                f"mcp__{SUBMISSION_SERVER_NAME}__{SUBMIT_PATCH_TOOL}",
                {"user_task": "patched"},
            )
            self.event_handler.on_usage({"input_tokens": 1, "output_tokens": 2})
            return "user_task: patched"

    import agentshim

    monkeypatch.setattr(agentshim, "CodingAgent", FakeCodingAgent)
    config = AgentConfig(provider="codex", model="gpt-test")
    runner = AgentshimRunner(role="attacker", config=config)
    scenario = AttackScenario.model_validate(valid_scenario_data())

    runner.propose_patch(scenario, attempt=1, previous_attempts=[], output_dir=tmp_path)

    assert (tmp_path / "attacker_stream.txt").read_text(encoding="utf-8") == "drafting scenario\n"
    events = (tmp_path / "attacker_events.jsonl").read_text(encoding="utf-8")
    assert '"event": "thinking"' in events
    assert '"event": "usage"' in events


def test_agentshim_attacker_adapter_asks_again_when_submission_tool_is_missing(monkeypatch) -> None:
    prompts = []

    class FakeCodingAgent:
        def __init__(self, **kwargs):
            self.event_handler = kwargs["event_handler"]

        def generate(self, prompt, cwd=None, silent=False):
            prompts.append(prompt)
            if len(prompts) == 2:
                self.event_handler.on_tool_call(
                    f"mcp__{SUBMISSION_SERVER_NAME}__{SUBMIT_SCENARIO_TOOL}",
                    {
                        "id": "submitted",
                        "seed": {
                            "user_task": "Do work.",
                            "attacker_task": "Trigger sink.",
                            "max_attempts": 1,
                        },
                        "environment": {
                            "mcp_servers": [
                                {
                                    "name": "email",
                                    "tools": [
                                        {
                                            "name": "send_email",
                                            "args_schema": {"type": "object", "additionalProperties": True},
                                        }
                                    ],
                                }
                            ]
                        },
                        "oracles": [{"type": "tool_invoked", "tool_name": "email.send_email"}],
                    },
                )
            return "not submitted"

    import agentshim

    monkeypatch.setattr(agentshim, "CodingAgent", FakeCodingAgent)
    config = AgentConfig(provider="claude", model="opus")
    experiment = ExperimentConfig.model_validate(
        {
            "id": "submit-test",
            "agents": {"attacker": {"provider": "claude"}, "victim": {"provider": "fake"}},
        }
    )
    runner = AgentshimRunner(role="attacker", config=config)

    response = runner.propose_scenario(experiment, attempt=1, previous_attempts=[])

    assert len(prompts) == 2
    assert "did not call the required MCP tool" in prompts[1]
    assert "id: submitted" in response


def test_agentshim_attacker_adapter_uses_same_session_for_missing_submission(monkeypatch) -> None:
    prompts = []
    sessions_started = []

    class FakeSession:
        def __init__(self, event_handler):
            self.event_handler = event_handler

        def generate(self, prompt, cwd=None, timeout=None, silent=None, on_process_started=None):
            prompts.append(prompt)
            if len(prompts) == 2:
                self.event_handler.on_tool_call(
                    f"mcp__{SUBMISSION_SERVER_NAME}__{SUBMIT_PATCH_TOOL}",
                    {"user_task": "submitted in same session"},
                )
            return "text response"

    class FakeCodingAgent:
        def __init__(self, **kwargs):
            self.event_handler = kwargs["event_handler"]

        def start_session(self, cwd=None, timeout=300, silent=False):
            sessions_started.append((cwd, silent))
            return FakeSession(self.event_handler)

    import agentshim

    monkeypatch.setattr(agentshim, "CodingAgent", FakeCodingAgent)
    config = AgentConfig(provider="claude", model="opus")
    runner = AgentshimRunner(role="attacker", config=config)
    scenario = AttackScenario.model_validate(valid_scenario_data())

    response = runner.propose_patch(scenario, attempt=1, previous_attempts=[])

    assert sessions_started == [(".", True)]
    assert len(prompts) == 2
    assert "did not call the required MCP tool" in prompts[1]
    assert response == "user_task: submitted in same session\n"


def test_codex_reasoning_effort_is_injected_into_command() -> None:
    class FakeBackend:
        def _get_command(self, prompt, resume_session_id=None):
            return ["codex", "exec", "--json", "--model", "gpt-5.5", "-"]

    class FakeCodingAgent:
        def __init__(self, **kwargs):
            self.backend = FakeBackend()

    config = AgentConfig(provider="codex", model="gpt-5.5", reasoning_effort="xhigh")

    agent = _make_coding_agent(FakeCodingAgent, config)

    assert agent.backend._get_command("prompt") == [
        "codex",
        "exec",
        "--json",
        "-c",
        'model_reasoning_effort="xhigh"',
        "--model",
        "gpt-5.5",
        "-",
    ]


def test_recover_yaml_from_stream_handles_codex_suffix(tmp_path) -> None:
    (tmp_path / "attacker_stream.txt").write_text(
        "thinking\nid: recovered\nseed:\n  user_task: hi\n[codex turn complete]",
        encoding="utf-8",
    )

    assert _recover_yaml_from_stream(tmp_path, "attacker") == "id: recovered\nseed:\n  user_task: hi"


def test_recover_yaml_from_events_handles_tool_result_stdout(tmp_path) -> None:
    (tmp_path / "attacker_events.jsonl").write_text(
        '{"event": "tool_result", "stdout": "validated\\nid: recovered\\nseed:\\n  user_task: hi"}\n',
        encoding="utf-8",
    )

    assert _recover_yaml_from_stream(tmp_path, "attacker") == "id: recovered\nseed:\n  user_task: hi"


def test_scenario_generation_prompt_references_previous_attempt_paths(tmp_path) -> None:
    config = ExperimentConfig.model_validate(
        {
            "id": "prompt-history",
            "agents": {"attacker": {"provider": "fake"}, "victim": {"provider": "fake"}},
        }
    )
    previous = [
        AttemptRecord(
            attempt=1,
            success=False,
            patch_error="oracle failed",
            victim_output="large victim transcript should not be embedded",
        )
    ]
    attempt_dir = tmp_path / "attempt-002"

    prompt = _scenario_generation_prompt(config, attempt=2, previous_attempts=previous, output_dir=attempt_dir)

    assert str(tmp_path) in prompt
    assert "attempt-NNN" in prompt
    assert "total_attempts: 1" in prompt
    assert "oracle failed" not in prompt
    assert "large victim transcript should not be embedded" not in prompt
