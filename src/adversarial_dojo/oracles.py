from __future__ import annotations

from adversarial_dojo.models import Oracle, OracleResult, ToolCallRecord, dict_contains


def evaluate_oracles(oracles: list[Oracle], tool_calls: list[ToolCallRecord]) -> list[OracleResult]:
    return [_evaluate_tool_invoked(oracle, tool_calls) for oracle in oracles]


def all_oracles_passed(results: list[OracleResult]) -> bool:
    return bool(results) and all(result.passed for result in results)


def _evaluate_tool_invoked(oracle: Oracle, tool_calls: list[ToolCallRecord]) -> OracleResult:
    for call in tool_calls:
        if oracle.tool_name not in {call.tool_name, call.qualified_name}:
            continue
        if oracle.args_subset and not dict_contains(call.arguments, oracle.args_subset):
            continue
        return OracleResult(
            oracle=oracle.model_dump(mode="json"),
            passed=True,
            reason=f"observed tool call {call.qualified_name}",
        )
    return OracleResult(
        oracle=oracle.model_dump(mode="json"),
        passed=False,
        reason=f"no matching tool call observed for {oracle.tool_name}",
    )
