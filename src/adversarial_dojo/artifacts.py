from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from adversarial_dojo.models import (
    AttackScenario,
    AttemptRecord,
    BenchmarkResult,
    ExperimentConfig,
)
from adversarial_dojo.runner import (
    _append_attempt,
    _attempt_dir,
    _write_attempt_artifacts,
    _write_json,
    _write_text,
)


@dataclass
class SearchArtifactStore:
    root: Path | None
    attempts_path: Path | None

    @classmethod
    def open(
        cls,
        config: ExperimentConfig,
        output_dir: str | Path | None,
        *,
        resume: bool,
    ) -> SearchArtifactStore:
        root = Path(output_dir) if output_dir is not None else None
        if root is None:
            return cls(root=None, attempts_path=None)
        root.mkdir(parents=True, exist_ok=True)
        attempts_path = root / "attempts.jsonl"
        if not resume or not attempts_path.exists():
            attempts_path.write_text("", encoding="utf-8")
        store = cls(root=root, attempts_path=attempts_path)
        store.write_config(config)
        return store

    def attempt_dir(self, attempt_number: int) -> Path | None:
        return _attempt_dir(self.root, attempt_number)

    def load_attempts(self) -> list[AttemptRecord]:
        if self.attempts_path is None or not self.attempts_path.exists():
            return []
        attempts: list[AttemptRecord] = []
        for line in self.attempts_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                attempts.append(AttemptRecord.model_validate_json(line))
        return attempts

    def write_config(self, config: ExperimentConfig) -> None:
        _write_json(self.root, "config.json", config.model_dump(mode="json"))

    def write_summary(self, result: BenchmarkResult) -> None:
        _write_json(
            self.root,
            "summary.json",
            result.model_dump(mode="json", exclude={"attempts"}),
        )

    def write_raw_scenario(self, attempt_number: int, text: str) -> None:
        _write_text(
            self.attempt_dir(attempt_number),
            "red_team_scenario.raw.txt",
            text,
        )

    def write_repair_scenario(self, attempt_number: int, text: str) -> None:
        _write_text(
            self.attempt_dir(attempt_number),
            "red_team_repair_scenario.raw.txt",
            text,
        )

    def write_runtime_secrets(self, attempt_number: int, redacted: dict[str, str]) -> None:
        _write_json(
            self.attempt_dir(attempt_number),
            "runtime_secrets.json",
            redacted,
        )

    def write_attempt(
        self,
        attempt_number: int,
        record: AttemptRecord,
        scenario: AttackScenario | None,
    ) -> None:
        _write_attempt_artifacts(
            self.attempt_dir(attempt_number),
            record=record,
            scenario=scenario,
        )

    def append_attempt_record(self, record: AttemptRecord) -> None:
        _append_attempt(self.attempts_path, record)


@dataclass
class AttackSearchRecorder:
    attempts: list[AttemptRecord]
    artifact_store: SearchArtifactStore

    def record(
        self,
        *,
        scenario: AttackScenario | None,
        record: AttemptRecord,
        attempt_number: int,
        analysis_callback: Callable[[], None] | None = None,
    ) -> None:
        self.artifact_store.write_attempt(attempt_number, record, scenario)
        if analysis_callback is not None:
            analysis_callback()
            self.artifact_store.write_attempt(attempt_number, record, scenario)
        self.attempts.append(record)
        self.artifact_store.append_attempt_record(record)
