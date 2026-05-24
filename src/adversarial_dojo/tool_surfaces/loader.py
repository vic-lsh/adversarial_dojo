from __future__ import annotations

from pathlib import Path

from adversarial_dojo.models import MockEnvironment
from adversarial_dojo.tool_surfaces.proto import load_proto_tool_surface


def load_tool_surface_file(path: str | Path) -> MockEnvironment:
    surface_path = Path(path)
    if surface_path.suffix.lower() != ".proto":
        raise ValueError(
            f"tool surface files must use the .proto extension, got: {surface_path.suffix}"
        )
    return load_proto_tool_surface(surface_path)
