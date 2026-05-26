from __future__ import annotations

from pathlib import Path

from adversarial_dojo.tool_interfaces.models import ToolInterface
from adversarial_dojo.tool_interfaces.proto import load_proto_tool_interface


def load_tool_interface_file(path: str | Path) -> ToolInterface:
    interface_path = Path(path)
    if interface_path.suffix.lower() != ".proto":
        raise ValueError(
            f"tool interface files must use the .proto extension, got: {interface_path.suffix}"
        )
    return load_proto_tool_interface(interface_path)
