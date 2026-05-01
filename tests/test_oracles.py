from __future__ import annotations

from adversarial_dojo.models import ToolCallRecord, ToolInvokedOracle
from adversarial_dojo.oracles import evaluate_oracles


def test_tool_invoked_oracle_matches_qualified_name_and_argument_subset() -> None:
    oracle = ToolInvokedOracle(tool_name="email.send_email", args_subset={"to": "a@example.com"})
    calls = [
        ToolCallRecord(
            server_name="email",
            tool_name="send_email",
            arguments={"to": "a@example.com", "body": "hello"},
        )
    ]

    results = evaluate_oracles([oracle], calls)

    assert results[0].passed is True


def test_tool_invoked_oracle_fails_when_arguments_do_not_match() -> None:
    oracle = ToolInvokedOracle(tool_name="send_email", args_subset={"to": "a@example.com"})
    calls = [
        ToolCallRecord(server_name="email", tool_name="send_email", arguments={"to": "b@example.com"})
    ]

    results = evaluate_oracles([oracle], calls)

    assert results[0].passed is False
