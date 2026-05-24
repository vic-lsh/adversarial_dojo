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
    run_parser.add_argument("--attacker-provider", default=None)
    run_parser.add_argument("--attacker-model", default=None)
    run_parser.add_argument("--victim-provider", default=None)
    run_parser.add_argument("--victim-model", default=None)

    attack_parser = subparsers.add_parser("attack", help="Run open-ended attacker-generated scenario search.")
    attack_parser.add_argument("config")
    attack_parser.add_argument("--out", default=None)
    attack_parser.add_argument("--attacker-provider", default=None)
    attack_parser.add_argument("--attacker-model", default=None)
    attack_parser.add_argument("--victim-provider", default=None)
    attack_parser.add_argument("--victim-model", default=None)
    attack_parser.add_argument("--attacker-guidance", default=None)
    attack_parser.add_argument("--attacker-guidance-file", default=None)
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

    if args.command == "attack":
        try:
            config = ExperimentConfig.from_toml_file(args.config)
        except (OSError, ValidationError, ValueError) as exc:
            print(f"invalid config: {exc}", file=sys.stderr)
            return 2
        try:
            overrides = _attack_overrides(args)
        except OSError as exc:
            print(f"invalid config: {exc}", file=sys.stderr)
            return 2
        try:
            validate_supported_config(apply_config_overrides(config, overrides))
        except ValueError as exc:
            print(f"invalid config: {exc}", file=sys.stderr)
            return 2
        out = args.out or str(Path("runs") / config.id)
        result = run_attack_search(config, overrides=overrides, output_dir=out, resume=args.resume)
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

    overrides = _agent_overrides(args)
    try:
        validate_supported_runtime(apply_overrides(scenario, overrides))
    except ValueError as exc:
        print(f"invalid scenario: {exc}", file=sys.stderr)
        return 2

    out = args.out or str(Path("runs") / scenario.id)
    result = run_benchmark(
        scenario,
        overrides=overrides,
        output_dir=out,
    )
    print(json.dumps(result.model_dump(mode="json", exclude={"attempts"}), indent=2))
    return 0


def _agent_overrides(args: argparse.Namespace) -> dict[str, str | None]:
    return {
        "attacker_provider": args.attacker_provider,
        "attacker_model": args.attacker_model,
        "victim_provider": args.victim_provider,
        "victim_model": args.victim_model,
    }


def _attack_overrides(args: argparse.Namespace) -> dict[str, str | None]:
    overrides = _agent_overrides(args)
    guidance_parts: list[str] = []
    if args.attacker_guidance:
        guidance_parts.append(args.attacker_guidance)
    if args.attacker_guidance_file:
        guidance_parts.append(Path(args.attacker_guidance_file).read_text(encoding="utf-8"))
    if guidance_parts:
        overrides["red_team_guidance"] = "\n\n".join(part.strip() for part in guidance_parts if part.strip())
    return overrides


if __name__ == "__main__":
    raise SystemExit(main())
