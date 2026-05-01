from __future__ import annotations

import json
import tomllib
from pathlib import Path

import yaml

from adversarial_dojo.models import MockEnvironment


def load_tool_surface_file(path: str | Path) -> MockEnvironment:
    surface_path = Path(path)
    suffix = surface_path.suffix.lower()
    if suffix == ".toml":
        data = _load_toml(surface_path)
    elif suffix in {".yaml", ".yml"}:
        data = _load_yaml(surface_path)
    elif suffix == ".json":
        data = _load_json(surface_path)
    elif suffix == ".proto":
        from adversarial_dojo.tool_surfaces.proto import load_proto_tool_surface

        return load_proto_tool_surface(surface_path)
    else:
        raise ValueError(f"unsupported tool surface file extension: {surface_path.suffix}")
    if not isinstance(data, dict):
        raise ValueError("tool surface file must contain a mapping")
    if "tool_surface" in data:
        data = data["tool_surface"]
    return MockEnvironment.model_validate(data)


def _load_toml(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def _load_yaml(path: Path) -> object:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _load_json(path: Path) -> object:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)
