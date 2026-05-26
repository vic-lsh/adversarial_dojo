from __future__ import annotations

from adversarial_dojo.agents.agentshim import AgentshimRunner
from adversarial_dojo.agents.fake import FakeAgentRunner
from adversarial_dojo.config import AgentConfig


def make_runner(role: str, config: AgentConfig) -> FakeAgentRunner | AgentshimRunner:
    if config.provider == "fake":
        return FakeAgentRunner(role=role, config=config)
    return AgentshimRunner(role=role, config=config)
