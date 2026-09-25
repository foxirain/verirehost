from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .artifact_binding import bind
from .errors import RehostError
from .exact_slice import run_exact_slice
from .kernel_preflight import inspect
from .profile import load
from .receipt import read, verify, write
from .state_space import explore_scenario, load_scenario


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def integer(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer: {value}") from exc


def register_assignment(value: str) -> tuple[str, int]:
    name, separator, raw = value.partition("=")
    if not separator or not name:
        raise argparse.ArgumentTypeError("register values use NAME=VALUE")
    return name.lower(), integer(raw)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="verirehost",
        description="Evidence-first primitives for selective AArch64 firmware rehosting.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate-profile", help="validate generic rehosting metadata")
    validate.add_argument("profile", type=Path)

    receipt = sub.add_parser("verify-receipt", help="verify content-addressed receipts")
    receipt.add_argument("receipts", nargs="+", type=Path)

    binding = sub.add_parser("bind-artifact", help="bind a private artifact to public metadata")
    binding.add_argument("profile", type=Path)
    binding.add_argument("role")
    binding.add_argument("path", type=Path)
    binding.add_argument("--output", type=Path, required=True)

    exact = sub.add_parser(
        "run-exact-slice",
        help="execute a hash-recorded, fail-closed AArch64 slice without target services",
    )
    exact.add_argument("artifact", type=Path)
    exact.add_argument("--target-id", required=True)
    exact.add_argument("--image-base", type=integer, required=True)
    exact.add_argument("--entry", type=integer, required=True)
    exact.add_argument("--stop-exclusive", type=integer, required=True)
    exact.add_argument("--stack-base", type=integer, required=True)
    exact.add_argument("--stack-size", type=integer, default=0x10000)
    exact.add_argument("--max-instructions", type=int, default=256)
    exact.add_argument(
        "--register",
        type=register_assignment,
        action="append",
        default=[],
        metavar="NAME=VALUE",
    )
    exact.add_argument("--output", type=Path, required=True)

    preflight = sub.add_parser(
        "preflight-kernel",
        help="evaluate a kernel configuration for the generic QEMU USB lane",
    )
    preflight.add_argument("config", type=Path)
    preflight.add_argument("--output", type=Path, required=True)
    preflight.add_argument("--model", default="unspecified")
    preflight.add_argument("--build", default="unspecified")

    state_space = sub.add_parser(
        "explore-state-space",
        help="exhaustively explore a bounded abstract transition model",
    )
    state_space.add_argument("scenario", type=Path)
    state_space.add_argument("--output", type=Path, required=True)
    return parser


def _initial_registers(values: list[tuple[str, int]]) -> dict[str, int]:
    result: dict[str, int] = {}
    for name, value in values:
        if name in result:
            raise RehostError(
                "EXACT_REGISTER",
                "an initial register was declared more than once",
                {"register": name},
            )
        result[name] = value
    return result


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "validate-profile":
            profile, _ = load(args.profile)
            print(json.dumps({"valid": True, "profile_id": profile["id"]}, sort_keys=True))
            return 0

        if args.command == "verify-receipt":
            for path in args.receipts:
                value = read(path)
                verify(value)
                print(
                    json.dumps(
                        {
                            "valid": True,
                            "path": str(path),
                            "content_id": value["content_id"],
                        },
                        sort_keys=True,
                    )
                )
            return 0

        if args.command == "bind-artifact":
            profile, raw = load(args.profile)
            value = bind(profile, raw, args.role, args.path)
            write(args.output, value)
            print(
                json.dumps(
                    {
                        "status": value["status"],
                        "output": str(args.output),
                        "content_id": value["content_id"],
                    },
                    sort_keys=True,
                )
            )
            return 0 if value["status"] == "matched" else 1

        if args.command == "run-exact-slice":
            value = run_exact_slice(
                args.artifact,
                target={"id": args.target_id, "architecture": "aarch64"},
                image_base=args.image_base,
                entry=args.entry,
                stop_exclusive=args.stop_exclusive,
                stack_base=args.stack_base,
                stack_size=args.stack_size,
                initial_registers=_initial_registers(args.register),
                max_instructions=args.max_instructions,
            )
            write(args.output, value)
            print(
                json.dumps(
                    {
                        "status": value["status"],
                        "output": str(args.output),
                        "content_id": value["content_id"],
                    },
                    sort_keys=True,
                )
            )
            return 0

        if args.command == "preflight-kernel":
            value = inspect(args.config, {"model": args.model, "build": args.build})
            write(args.output, value)
            print(
                json.dumps(
                    {
                        "status": value["status"],
                        "output": str(args.output),
                        "content_id": value["content_id"],
                    },
                    sort_keys=True,
                )
            )
            return 0 if value["status"] == "compatible" else 1

        if args.command == "explore-state-space":
            value = explore_scenario(load_scenario(args.scenario))
            write(args.output, value)
            print(
                json.dumps(
                    {
                        "status": value["status"],
                        "output": str(args.output),
                        "content_id": value["content_id"],
                        "complete": value["exploration"]["complete"],
                    },
                    sort_keys=True,
                )
            )
            return 0 if value["exploration"]["complete"] else 1

        raise AssertionError(f"unhandled command: {args.command}")
    except RehostError as exc:
        print(json.dumps(exc.as_dict(), sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
