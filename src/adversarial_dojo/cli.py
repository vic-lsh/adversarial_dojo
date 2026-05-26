from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from adversarial_dojo.config import ExperimentConfig
from adversarial_dojo.experiment import run_attack_search, validate_supported_config
from adversarial_dojo.scenario import Scenario


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="adversarial-dojo")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_config_parser = subparsers.add_parser(
        "validate-config",
        help="Validate a TOML experiment config.",
    )
    validate_config_parser.add_argument("config")

    validate_scenario_parser = subparsers.add_parser(
        "validate-scenario",
        help="Validate a prepared scenario YAML/JSON file.",
    )
    validate_scenario_parser.add_argument("scenario")

    search_parser = subparsers.add_parser(
        "search-attacks",
        help="Search for attacks: red-team agent generates scenarios and runs them against the victim.",
    )
    search_parser.add_argument("config")
    search_parser.add_argument("--out", default=None)
    search_parser.add_argument("--red-team-provider", dest="red_team_provider", default=None)
    search_parser.add_argument("--red-team-model", dest="red_team_model", default=None)
    search_parser.add_argument("--victim-provider", default=None)
    search_parser.add_argument("--victim-model", default=None)
    search_parser.add_argument("--analyzer-provider", default=None)
    search_parser.add_argument("--analyzer-model", default=None)
    search_parser.add_argument("--red-team-guidance", dest="red_team_guidance", default=None)
    search_parser.add_argument("--red-team-guidance-file", dest="red_team_guidance_file", default=None)
    search_parser.add_argument("--resume", action="store_true", help="Resume an existing attack run directory.")

    args = parser.parse_args(argv)

    if args.command == "validate-scenario":
        try:
            scenario = Scenario.from_yaml_file(args.scenario)
        except (OSError, ValidationError, ValueError) as exc:
            print(f"invalid scenario: {exc}", file=sys.stderr)
            return 2
        print(f"valid scenario: {scenario.id}")
        return 0

    try:
        config = ExperimentConfig.from_toml_file(args.config)
    except (OSError, ValidationError, ValueError) as exc:
        print(f"invalid config: {exc}", file=sys.stderr)
        return 2

    if args.command == "validate-config":
        try:
            validate_supported_config(config)
        except ValueError as exc:
            print(f"invalid config: {exc}", file=sys.stderr)
            return 2
        print(f"valid config: {config.id}")
        return 0

    try:
        config = apply_config_overrides(config, _search_overrides(args))
        validate_supported_config(config)
    except (OSError, ValueError, ValidationError) as exc:
        print(f"invalid config: {exc}", file=sys.stderr)
        return 2
    out = args.out or str(Path("runs") / config.id)
    result = run_attack_search(config, output_dir=out, resume=args.resume)
    print(json.dumps(result.model_dump(mode="json", exclude={"attempts"}), indent=2))
    return 0


def _search_overrides(args: argparse.Namespace) -> dict[str, str | None]:
    overrides = {
        "red_team_provider": args.red_team_provider,
        "red_team_model": args.red_team_model,
        "victim_provider": args.victim_provider,
        "victim_model": args.victim_model,
        "analyzer_provider": args.analyzer_provider,
        "analyzer_model": args.analyzer_model,
    }
    guidance_parts: list[str] = []
    if args.red_team_guidance:
        guidance_parts.append(args.red_team_guidance)
    if args.red_team_guidance_file:
        guidance_parts.append(Path(args.red_team_guidance_file).read_text(encoding="utf-8"))
    if guidance_parts:
        overrides["red_team_guidance"] = "\n\n".join(
            part.strip() for part in guidance_parts if part.strip()
        )
    return overrides


def apply_config_overrides(
    config: ExperimentConfig,
    overrides: dict[str, Any],
) -> ExperimentConfig:
    if not overrides:
        return config
    data = config.model_dump(mode="json")
    data["tool_interface_source_files"] = list(config.tool_interface_source_files)
    _override_agent(data["agents"]["red_team"], overrides, "red_team")
    _override_agent(data["agents"]["victim"], overrides, "victim")
    analyzer_provider = overrides.get("analyzer_provider")
    analyzer_model = overrides.get("analyzer_model")
    if analyzer_provider or analyzer_model:
        analyzer_data = data["agents"].get("analyzer")
        if analyzer_data is None:
            analyzer_data = dict(data["agents"]["red_team"])
        _override_agent(analyzer_data, overrides, "analyzer")
        data["agents"]["analyzer"] = analyzer_data
    if overrides.get("red_team_guidance") is not None:
        data["benchmark"]["red_team_guidance"] = overrides["red_team_guidance"]
    return ExperimentConfig.model_validate(data)


def _override_agent(agent_data: dict[str, Any], overrides: dict[str, Any], role: str) -> None:
    provider = overrides.get(f"{role}_provider")
    model = overrides.get(f"{role}_model")
    if provider:
        agent_data["provider"] = provider
    if model:
        agent_data["model"] = model


if __name__ == "__main__":
    raise SystemExit(main())
