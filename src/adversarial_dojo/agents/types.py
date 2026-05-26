from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

from adversarial_dojo.config import ExperimentConfig
from adversarial_dojo.records import AgentRunResult, AttemptAnalysis, AttemptRecord
from adversarial_dojo.scenario import Scenario


class RedTeamRunner(Protocol):
    def propose_scenario(
        self,
        config: ExperimentConfig,
        attempt: int,
        previous_attempts: list[Any],
        repair_error: str | None = None,
        output_dir: Path | None = None,
    ) -> str:
        ...

    def analyze_attempt(
        self,
        config: ExperimentConfig,
        scenario: Scenario | None,
        record: AttemptRecord,
        attempt: int,
        attempt_dir: Path,
        output_dir: Path | None = None,
    ) -> AttemptAnalysis:
        ...


class VictimRunner(Protocol):
    def run_victim(
        self,
        scenario: Scenario,
        attempt: int,
        output_dir: Path | None = None,
    ) -> AgentRunResult:
        ...
