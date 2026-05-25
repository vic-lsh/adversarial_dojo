from __future__ import annotations

from adversarial_dojo.models import AttackScenario, Evaluator, EvaluatorResult, ToolCallRecord


def run_evaluators(
    evaluators: list[Evaluator],
    tool_calls: list[ToolCallRecord],
    scenario: AttackScenario | None = None,
    runtime_secrets: dict[str, str] | None = None,
) -> list[EvaluatorResult]:
    secrets = runtime_secrets or {}
    return [
        evaluator.run(
            tool_calls=tool_calls,
            scenario=scenario,
            runtime_secrets=secrets,
        )
        for evaluator in evaluators
    ]


def all_evaluators_passed(results: list[EvaluatorResult]) -> bool:
    return bool(results) and all(result.passed for result in results)
