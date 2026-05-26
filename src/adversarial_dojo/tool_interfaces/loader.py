from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import Field

from adversarial_dojo.common import StrictModel
from adversarial_dojo.tool_interfaces.models import SinkCapability, ToolInterface
from adversarial_dojo.tool_interfaces.proto import load_proto_tool_interface


class ToolInterfaceBundle(StrictModel):
    proto: str = Field(min_length=1)
    sink_capabilities: list[SinkCapability] = Field(default_factory=list)


def load_tool_interface_file(path: str | Path) -> ToolInterface:
    interface_path = Path(path)
    suffix = interface_path.suffix.lower()
    if suffix == ".proto":
        return load_proto_tool_interface(interface_path)
    if suffix in {".yaml", ".yml"}:
        return _load_tool_interface_bundle(interface_path)
    raise ValueError(
        "tool interface files must use the .proto, .yaml, or .yml extension, "
        f"got: {interface_path.suffix}"
    )


def tool_interface_source_files(path: str | Path) -> list[Path]:
    interface_path = Path(path)
    suffix = interface_path.suffix.lower()
    if suffix == ".proto":
        return [interface_path]
    if suffix in {".yaml", ".yml"}:
        with interface_path.open("r", encoding="utf-8") as handle:
            data: Any = yaml.safe_load(handle)
        if not isinstance(data, dict):
            raise ValueError("tool interface bundle must be a mapping")
        bundle = ToolInterfaceBundle.model_validate(data)
        proto_path = Path(bundle.proto).expanduser()
        if not proto_path.is_absolute():
            proto_path = interface_path.parent / proto_path
        return [interface_path, proto_path]
    raise ValueError(
        "tool interface files must use the .proto, .yaml, or .yml extension, "
        f"got: {interface_path.suffix}"
    )


def _load_tool_interface_bundle(path: Path) -> ToolInterface:
    with path.open("r", encoding="utf-8") as handle:
        data: Any = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise ValueError("tool interface bundle must be a mapping")
    bundle = ToolInterfaceBundle.model_validate(data)
    proto_path = Path(bundle.proto).expanduser()
    if not proto_path.is_absolute():
        proto_path = path.parent / proto_path
    interface = load_proto_tool_interface(proto_path)
    return ToolInterface(
        servers=interface.servers,
        sink_capabilities=bundle.sink_capabilities,
    )
