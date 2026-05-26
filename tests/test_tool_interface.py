from __future__ import annotations

import pytest
from pydantic import ValidationError

from adversarial_dojo.config import ExperimentConfig
from adversarial_dojo.tool_interfaces import load_tool_interface_file


def test_proto_loader_builds_tool_interface() -> None:
    interface = load_tool_interface_file("examples/tool_interfaces/fake_workspace.proto")

    assert "docs.read_note" in interface.qualified_tool_names
    assert "email.send_email" in interface.qualified_tool_names
    assert interface.sink_capabilities == []
    _, send_email = interface.find_tool("email.send_email")
    assert "body" in send_email.args_schema["properties"]


def test_yaml_loader_builds_tool_interface_with_sink_capabilities() -> None:
    interface = load_tool_interface_file("examples/tool_interfaces/fake_workspace.yaml")

    assert "docs.read_note" in interface.qualified_tool_names
    capability = interface.find_sink_capability("email.send_email")
    assert capability is not None
    assert capability.payload_fields == ["body", "subject"]
    assert capability.match_fields == ["to"]
    assert capability.destination_kinds == ["inbox", "email_inbox"]


def test_experiment_config_requires_tool_interface(tmp_path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
id = "missing-interface"

[agents.red_team]
provider = "fake"

[agents.victim]
provider = "fake"
""",
        encoding="utf-8",
    )

    with pytest.raises(ValidationError, match="tool_interface"):
        ExperimentConfig.from_toml_file(config_path)


def test_experiment_config_rejects_ambiguous_tool_interface(tmp_path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
id = "ambiguous"
tool_interface_file = "surface.proto"

[agents.red_team]
provider = "fake"

[agents.victim]
provider = "fake"

[tool_interface]
servers = []
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="either tool_interface or tool_interface_file"):
        ExperimentConfig.from_toml_file(config_path)


def test_tool_interface_loader_rejects_unknown_extensions(tmp_path) -> None:
    surface_path = tmp_path / "surface.json"
    surface_path.write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match=".proto, .yaml, or .yml"):
        load_tool_interface_file(surface_path)
