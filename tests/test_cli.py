from __future__ import annotations

import json

from adversarial_dojo.cli import main


def test_cli_validate_config_accepts_tool_interface_file(capsys) -> None:
    exit_code = main(["validate-config", "examples/fake_open_search.toml"])

    assert exit_code == 0
    assert "valid config" in capsys.readouterr().out


def test_cli_search_attacks_runs_fake_config(tmp_path) -> None:
    out_dir = tmp_path / "run"

    exit_code = main(
        ["search-attacks", "examples/fake_open_search.toml", "--out", str(out_dir)]
    )

    assert exit_code == 0
    summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["success"] is True
    assert (out_dir / "attempt-001" / "resource_store.final.json").exists()
