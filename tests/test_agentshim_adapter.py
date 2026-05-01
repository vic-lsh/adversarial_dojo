from __future__ import annotations

from adversarial_dojo.agents import AgentshimRunner, _make_coding_agent, _recover_yaml_from_stream, _scenario_generation_prompt
from adversarial_dojo.models import AgentConfig, AttackScenario, AttemptRecord, ExperimentConfig
from tests.test_models import valid_scenario_data


def test_agentshim_attacker_adapter_wires_provider_model_and_backend_kwargs(monkeypatch) -> None:
    constructed = {}

    class FakeCodingAgent:
        def __init__(self, **kwargs):
            constructed.update(kwargs)

        def generate(self, prompt, cwd=None, silent=False):
            assert "AttackPatch" in prompt
            return "user_task: patched"

    import agentshim

    monkeypatch.setattr(agentshim, "CodingAgent", FakeCodingAgent)
    config = AgentConfig(provider="codex", model="gpt-test", backend_kwargs={"x": 1})
    runner = AgentshimRunner(role="attacker", config=config)
    scenario = AttackScenario.model_validate(valid_scenario_data())

    response = runner.propose_patch(scenario, attempt=1, previous_attempts=[])

    assert response == "user_task: patched"
    assert constructed["provider"] == "codex"
    assert constructed["model"] == "gpt-test"
    assert constructed["backend_kwargs"] == {"x": 1}


def test_agentshim_attacker_adapter_writes_streaming_trajectory(monkeypatch, tmp_path) -> None:
    class FakeCodingAgent:
        def __init__(self, **kwargs):
            self.event_handler = kwargs["event_handler"]

        def generate(self, prompt, cwd=None, silent=False):
            self.event_handler.on_thinking("drafting scenario\n")
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
