from __future__ import annotations

import argparse
import json
import sys
import warnings
from pathlib import Path

from pydantic import ValidationError

from adversarial_dojo.experiment import apply_config_overrides, run_attack_search, validate_supported_config
from adversarial_dojo.models import AttackScenario, ExperimentConfig
from adversarial_dojo.runner import apply_overrides, run_benchmark, validate_supported_runtime


_DEPRECATED_ALIASES = {
    "validate": "validate-scenario",
    "run": "replay",
    "attack": "search-attacks",
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="adversarial-dojo")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser(
        "validate-scenario",
        aliases=["validate"],
        help="Validate a YAML attack scenario.",
    )
    validate_parser.add_argument("scenario")

    validate_config_parser = subparsers.add_parser("validate-config", help="Validate a TOML experiment config.")
    validate_config_parser.add_argument("config")

    run_parser = subparsers.add_parser(
        "replay",
        aliases=["run"],
        help="Replay a pre-baked YAML attack scenario through the victim.",
    )
    run_parser.add_argument("scenario")
    run_parser.add_argument("--out", default=None)
    run_parser.add_argument("--red-team-provider", dest="red_team_provider", default=None)
    run_parser.add_argument("--red-team-model", dest="red_team_model", default=None)
    run_parser.add_argument(
        "--attacker-provider",
        dest="attacker_provider",
        default=None,
        help="Deprecated alias for --red-team-provider.",
    )
    run_parser.add_argument(
        "--attacker-model",
        dest="attacker_model",
        default=None,
        help="Deprecated alias for --red-team-model.",
    )
    run_parser.add_argument("--victim-provider", default=None)
    run_parser.add_argument("--victim-model", default=None)

    attack_parser = subparsers.add_parser(
        "search-attacks",
        aliases=["attack"],
        help="Search for attacks: red-team agent generates scenarios and runs them against the victim.",
    )
    attack_parser.add_argument("config")
    attack_parser.add_argument("--out", default=None)
    attack_parser.add_argument("--red-team-provider", dest="red_team_provider", default=None)
    attack_parser.add_argument("--red-team-model", dest="red_team_model", default=None)
    attack_parser.add_argument(
        "--attacker-provider",
        dest="attacker_provider",
        default=None,
        help="Deprecated alias for --red-team-provider.",
    )
    attack_parser.add_argument(
        "--attacker-model",
        dest="attacker_model",
        default=None,
        help="Deprecated alias for --red-team-model.",
    )
    attack_parser.add_argument("--victim-provider", default=None)
    attack_parser.add_argument("--victim-model", default=None)
    attack_parser.add_argument("--analyzer-provider", default=None)
    attack_parser.add_argument("--analyzer-model", default=None)
    attack_parser.add_argument("--red-team-guidance", dest="red_team_guidance", default=None)
    attack_parser.add_argument("--red-team-guidance-file", dest="red_team_guidance_file", default=None)
    attack_parser.add_argument(
        "--attacker-guidance",
        dest="attacker_guidance",
        default=None,
        help="Deprecated alias for --red-team-guidance.",
    )
    attack_parser.add_argument(
        "--attacker-guidance-file",
        dest="attacker_guidance_file",
        default=None,
        help="Deprecated alias for --red-team-guidance-file.",
    )
    attack_parser.add_argument("--resume", action="store_true", help="Resume an existing attack run directory.")

    args = parser.parse_args(argv)

    if args.command in _DEPRECATED_ALIASES:
        new_name = _DEPRECATED_ALIASES[args.command]
        warnings.warn(
            f"`{args.command}` is deprecated and will be removed in a future release; "
            f"use `{new_name}` instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        print(
            f"warning: `{args.command}` is deprecated; use `{new_name}` instead.",
            file=sys.stderr,
        )
        args.command = new_name

    if args.command == "validate-config":
        try:
            config = ExperimentConfig.from_toml_file(args.config)
            validate_supported_config(config)
        except (OSError, ValidationError, ValueError) as exc:
            print(f"invalid config: {exc}", file=sys.stderr)
            return 2
        print(f"valid config: {config.id}")
        return 0

    if args.command == "search-attacks":
        try:
            config = ExperimentConfig.from_toml_file(args.config)
        except (OSError, ValidationError, ValueError) as exc:
            print(f"invalid config: {exc}", file=sys.stderr)
            return 2
        try:
            config = apply_config_overrides(config, _attack_overrides(args))
        except (OSError, ValueError) as exc:
            print(f"invalid config: {exc}", file=sys.stderr)
            return 2
        try:
            validate_supported_config(config)
        except ValueError as exc:
            print(f"invalid config: {exc}", file=sys.stderr)
            return 2
        out = args.out or str(Path("runs") / config.id)
        result = run_attack_search(config, output_dir=out, resume=args.resume)
        print(json.dumps(result.model_dump(mode="json", exclude={"attempts"}), indent=2))
        return 0

    try:
        scenario = AttackScenario.from_yaml_file(args.scenario)
    except (OSError, ValidationError, ValueError) as exc:
        print(f"invalid scenario: {exc}", file=sys.stderr)
        return 2

    if args.command == "validate-scenario":
        try:
            validate_supported_runtime(scenario)
        except ValueError as exc:
            print(f"invalid scenario: {exc}", file=sys.stderr)
            return 2
        print(f"valid scenario: {scenario.id}")
        return 0

    scenario = apply_overrides(scenario, _agent_overrides(args))
    try:
        validate_supported_runtime(scenario)
    except ValueError as exc:
        print(f"invalid scenario: {exc}", file=sys.stderr)
        return 2

    out = args.out or str(Path("runs") / scenario.id)
    result = run_benchmark(scenario, output_dir=out)
    print(json.dumps(result.model_dump(mode="json", exclude={"attempts"}), indent=2))
    return 0


def _agent_overrides(args: argparse.Namespace) -> dict[str, str | None]:
    red_team_provider = getattr(args, "red_team_provider", None)
    red_team_model = getattr(args, "red_team_model", None)
    attacker_provider = getattr(args, "attacker_provider", None)
    attacker_model = getattr(args, "attacker_model", None)
    if attacker_provider is not None and red_team_provider is None:
        warnings.warn(
            "--attacker-provider is deprecated; use --red-team-provider.",
            DeprecationWarning,
            stacklevel=2,
        )
        red_team_provider = attacker_provider
    if attacker_model is not None and red_team_model is None:
        warnings.warn(
            "--attacker-model is deprecated; use --red-team-model.",
            DeprecationWarning,
            stacklevel=2,
        )
        red_team_model = attacker_model
    return {
        "red_team_provider": red_team_provider,
        "red_team_model": red_team_model,
        "victim_provider": args.victim_provider,
        "victim_model": args.victim_model,
    }


def _attack_overrides(args: argparse.Namespace) -> dict[str, str | None]:
    overrides = _agent_overrides(args)
    overrides["analyzer_provider"] = args.analyzer_provider
    overrides["analyzer_model"] = args.analyzer_model
    guidance_parts: list[str] = []
    red_team_guidance = getattr(args, "red_team_guidance", None)
    red_team_guidance_file = getattr(args, "red_team_guidance_file", None)
    attacker_guidance = getattr(args, "attacker_guidance", None)
    attacker_guidance_file = getattr(args, "attacker_guidance_file", None)
    if attacker_guidance is not None and red_team_guidance is None:
        warnings.warn(
            "--attacker-guidance is deprecated; use --red-team-guidance.",
            DeprecationWarning,
            stacklevel=2,
        )
        red_team_guidance = attacker_guidance
    if attacker_guidance_file is not None and red_team_guidance_file is None:
        warnings.warn(
            "--attacker-guidance-file is deprecated; use --red-team-guidance-file.",
            DeprecationWarning,
            stacklevel=2,
        )
        red_team_guidance_file = attacker_guidance_file
    if red_team_guidance:
        guidance_parts.append(red_team_guidance)
    if red_team_guidance_file:
        guidance_parts.append(Path(red_team_guidance_file).read_text(encoding="utf-8"))
    if guidance_parts:
        overrides["red_team_guidance"] = "\n\n".join(part.strip() for part in guidance_parts if part.strip())
    return overrides


if __name__ == "__main__":
    raise SystemExit(main())
