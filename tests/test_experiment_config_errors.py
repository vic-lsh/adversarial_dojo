"""Error-path tests for ExperimentConfig.from_toml_file().

Pins the failure surface of the experiment TOML loader so error messages
can't silently regress to opaque tracebacks, and so StrictModel's
extras-forbid behavior can't be silently relaxed by a future refactor.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest
from pydantic import ValidationError

from adversarial_dojo.models import ExperimentConfig


MINIMAL_AGENTS = """
[agents.red_team]
provider = "fake"

[agents.victim]
provider = "fake"
"""


VALID_PROTO = """
syntax = "proto3";
package dojo.workspace;

service Drive {
  rpc ReadDoc(ReadDocRequest) returns (ToolTextResponse);
}

message ReadDocRequest {
  string doc_id = 1;
}

message ToolTextResponse {
  string result = 1;
}
"""


def _write(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


# --- File-level errors ---------------------------------------------------


def test_missing_toml_file_raises_file_not_found(tmp_path: Path) -> None:
    missing = tmp_path / "nope.toml"
    with pytest.raises(FileNotFoundError) as exc_info:
        ExperimentConfig.from_toml_file(missing)
    assert str(missing) in str(exc_info.value)


def test_empty_toml_file_reports_missing_required_fields(tmp_path: Path) -> None:
    config_path = _write(tmp_path / "config.toml", "")
    with pytest.raises(ValidationError) as exc_info:
        ExperimentConfig.from_toml_file(config_path)
    message = str(exc_info.value)
    assert "id" in message
    assert "agents" in message


def test_malformed_toml_raises_decode_error(tmp_path: Path) -> None:
    config_path = _write(tmp_path / "config.toml", 'id = "unterminated')
    # Surfaces as a real TOML parse error rather than getting swallowed
    # into a confusing pydantic ValidationError.
    with pytest.raises(tomllib.TOMLDecodeError):
        ExperimentConfig.from_toml_file(config_path)


# --- Schema errors -------------------------------------------------------


def test_missing_required_top_level_field_id(tmp_path: Path) -> None:
    config_path = _write(tmp_path / "config.toml", MINIMAL_AGENTS)
    with pytest.raises(ValidationError) as exc_info:
        ExperimentConfig.from_toml_file(config_path)
    assert "id" in str(exc_info.value)


def test_missing_required_top_level_field_agents(tmp_path: Path) -> None:
    config_path = _write(tmp_path / "config.toml", 'id = "x"\n')
    with pytest.raises(ValidationError) as exc_info:
        ExperimentConfig.from_toml_file(config_path)
    assert "agents" in str(exc_info.value)


def test_wrong_scalar_type_is_rejected(tmp_path: Path) -> None:
    config_path = _write(
        tmp_path / "config.toml",
        'id = "x"\n' + MINIMAL_AGENTS + '\n[benchmark]\nmax_attempts = "five"\n',
    )
    with pytest.raises(ValidationError) as exc_info:
        ExperimentConfig.from_toml_file(config_path)
    message = str(exc_info.value)
    assert "max_attempts" in message
    assert "integer" in message


def test_wrong_container_type_is_rejected(tmp_path: Path) -> None:
    # ScenarioAgents.red_team must be a table, not a string.
    config_path = _write(
        tmp_path / "config.toml",
        'id = "x"\n[agents]\nred_team = "fake"\nvictim = {provider = "fake"}\n',
    )
    with pytest.raises(ValidationError) as exc_info:
        ExperimentConfig.from_toml_file(config_path)
    assert "red_team" in str(exc_info.value)


def test_unknown_top_level_field_is_rejected(tmp_path: Path) -> None:
    # Pins StrictModel(extra="forbid") on ExperimentConfig — a future
    # config-class refactor must not silently relax this.
    config_path = _write(
        tmp_path / "config.toml",
        'id = "x"\nbogus_field = true\n' + MINIMAL_AGENTS,
    )
    with pytest.raises(ValidationError) as exc_info:
        ExperimentConfig.from_toml_file(config_path)
    message = str(exc_info.value)
    assert "bogus_field" in message
    assert "Extra inputs are not permitted" in message


def test_unknown_nested_field_is_rejected(tmp_path: Path) -> None:
    # Same guard, one level deeper (AgentConfig).
    config_path = _write(
        tmp_path / "config.toml",
        'id = "x"\n[agents.red_team]\nprovider = "fake"\nmystery_knob = 1\n'
        '[agents.victim]\nprovider = "fake"\n',
    )
    with pytest.raises(ValidationError) as exc_info:
        ExperimentConfig.from_toml_file(config_path)
    message = str(exc_info.value)
    assert "mystery_knob" in message
    assert "Extra inputs are not permitted" in message


# --- Referenced-file errors ---------------------------------------------


def test_missing_tool_surface_file_path_surfaces_useful_error(tmp_path: Path) -> None:
    config_path = _write(
        tmp_path / "config.toml",
        'id = "x"\ntool_surface_file = "missing.proto"\n' + MINIMAL_AGENTS,
    )
    with pytest.raises(ValueError) as exc_info:
        ExperimentConfig.from_toml_file(config_path)
    # Current behavior: protoc reports the failure; the missing path appears
    # in the message so the user can locate the typo.
    assert "missing.proto" in str(exc_info.value)


def test_missing_red_team_guidance_file_surfaces_useful_error(tmp_path: Path) -> None:
    config_path = _write(
        tmp_path / "config.toml",
        'id = "x"\n' + MINIMAL_AGENTS
        + '\n[benchmark]\nred_team_guidance_file = "absent.txt"\n',
    )
    with pytest.raises(FileNotFoundError) as exc_info:
        ExperimentConfig.from_toml_file(config_path)
    assert "absent.txt" in str(exc_info.value)


def test_tool_surface_file_with_non_proto_extension_is_rejected(tmp_path: Path) -> None:
    _write(tmp_path / "surface.txt", "")
    config_path = _write(
        tmp_path / "config.toml",
        'id = "x"\ntool_surface_file = "surface.txt"\n' + MINIMAL_AGENTS,
    )
    with pytest.raises(ValueError, match=r"\.proto"):
        ExperimentConfig.from_toml_file(config_path)


def test_tool_surface_file_with_unparseable_proto_is_rejected(tmp_path: Path) -> None:
    _write(tmp_path / "surface.proto", "this is definitely not a valid proto file")
    config_path = _write(
        tmp_path / "config.toml",
        'id = "x"\ntool_surface_file = "surface.proto"\n' + MINIMAL_AGENTS,
    )
    with pytest.raises(ValueError) as exc_info:
        ExperimentConfig.from_toml_file(config_path)
    message = str(exc_info.value)
    assert "protoc" in message
    assert "surface.proto" in message


# --- Path-handling ------------------------------------------------------


def test_absolute_tool_surface_file_path_is_loaded(tmp_path: Path) -> None:
    surface_path = _write(tmp_path / "surface.proto", VALID_PROTO)
    config_path = _write(
        tmp_path / "config.toml",
        f'id = "x"\ntool_surface_file = "{surface_path}"\n' + MINIMAL_AGENTS,
    )
    config = ExperimentConfig.from_toml_file(config_path)
    assert config.tool_surface is not None
    assert config.tool_surface.mcp_servers[0].name == "drive"


def test_absolute_red_team_guidance_file_path_is_loaded(tmp_path: Path) -> None:
    notes_path = _write(tmp_path / "notes.txt", "Be subtle.")
    config_path = _write(
        tmp_path / "config.toml",
        'id = "x"\n' + MINIMAL_AGENTS
        + f'\n[benchmark]\nred_team_guidance_file = "{notes_path}"\n',
    )
    config = ExperimentConfig.from_toml_file(config_path)
    assert config.benchmark.red_team_guidance == "Be subtle."


def test_parent_segment_tool_surface_file_path_resolves_outside_config_dir(tmp_path: Path) -> None:
    # Pins current behavior: ".." segments are allowed; the path resolves
    # relative to the config's parent directory without sandboxing. This is
    # a deliberate-behavior marker — if we later sandbox to the config
    # directory, this test should flip to expect a rejection.
    outer = _write(tmp_path / "outer.proto", VALID_PROTO)
    config_dir = tmp_path / "inner"
    config_dir.mkdir()
    config_path = _write(
        config_dir / "config.toml",
        f'id = "x"\ntool_surface_file = "../{outer.name}"\n' + MINIMAL_AGENTS,
    )
    config = ExperimentConfig.from_toml_file(config_path)
    assert config.tool_surface is not None
    assert config.tool_surface.mcp_servers[0].name == "drive"
