#!/usr/bin/env python3
"""Run the redistributable exact-slice example from input through interpretation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from verirehost.artifact_binding import bind
from verirehost.canonical import canonical_bytes
from verirehost.errors import RehostError
from verirehost.exact_slice import run_exact_slice
from verirehost.profile import load
from verirehost.receipt import verify, write


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = PROJECT_ROOT / "fixtures" / "synthetic" / "aarch64-add-one.hex"
PROFILE = PROJECT_ROOT / "profiles" / "public-exact-slice-demo.json"


def _object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RehostError("DEMO_INPUT", f"{field} must be an object")
    return value


def _integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RehostError("DEMO_INPUT", f"{field} must be an integer")
    return value


def run(output_dir: Path) -> dict[str, Any]:
    profile, profile_bytes = load(PROFILE)
    experiment = _object(profile.get("experiment"), "profile experiment")
    initial_registers = _object(
        experiment.get("initial_registers"), "experiment initial_registers"
    )
    expected_final = _object(
        experiment.get("expected_final_registers"),
        "experiment expected_final_registers",
    )

    try:
        artifact_bytes = bytes.fromhex(FIXTURE.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RehostError("DEMO_INPUT", "unable to decode the public hex fixture") from exc

    output_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = output_dir / "synthetic-aarch64.bin"
    binding_path = output_dir / "binding.json"
    receipt_path = output_dir / "exact-slice.json"
    summary_path = output_dir / "summary.json"
    artifact_path.write_bytes(artifact_bytes)

    binding = bind(profile, profile_bytes, "firmware", artifact_path)
    if binding["status"] != "matched":
        raise RehostError("DEMO_BINDING", "the public fixture does not match its profile")
    verify(binding)
    write(binding_path, binding)

    target = {**_object(profile.get("target"), "profile target"), "id": profile["id"]}
    receipt = run_exact_slice(
        artifact_path,
        target=target,
        image_base=_integer(experiment.get("image_base"), "experiment image_base"),
        entry=_integer(experiment.get("entry"), "experiment entry"),
        stop_exclusive=_integer(
            experiment.get("stop_exclusive"), "experiment stop_exclusive"
        ),
        stack_base=_integer(experiment.get("stack_base"), "experiment stack_base"),
        stack_size=_integer(experiment.get("stack_size"), "experiment stack_size"),
        initial_registers={
            str(name): _integer(value, f"initial register {name}")
            for name, value in initial_registers.items()
        },
        max_instructions=_integer(
            experiment.get("max_instructions"), "experiment max_instructions"
        ),
    )
    verify(receipt)
    write(receipt_path, receipt)

    observed = receipt["execution"]["final_registers"]
    for name, expected in expected_final.items():
        if observed.get(name) != expected:
            raise RehostError(
                "DEMO_RESULT",
                "the public exact-slice result did not match the declared expectation",
                {"register": name, "expected": expected, "observed": observed.get(name)},
            )

    summary = {
        "schema": "verirehost/public-exact-slice-demo/v1",
        "status": "passed",
        "input": {
            "fixture": "fixtures/synthetic/aarch64-add-one.hex",
            "profile": "profiles/public-exact-slice-demo.json",
            "artifact_sha256": receipt["artifact"]["sha256"],
            "declared_initial_registers": receipt["initial_state"][
                "declared_registers"
            ],
        },
        "execution": {
            "engine": receipt["execution"]["engine"],
            "status": receipt["status"],
            "executed_instructions": receipt["budget"]["executed_instructions"],
            "executed_address_sha256": receipt["execution"][
                "executed_address_sha256"
            ],
        },
        "result": {
            "final_registers": observed,
            "expected_final_registers": expected_final,
        },
        "interpretation": [
            "The hash-bound public AArch64 slice incremented x0 from 41 to 42 and reached its declared stop.",
            "The sealed receipt binds the declared and effective initial register state.",
            "This is synthetic execution evidence, not vendor-firmware or physical-device evidence.",
        ],
        "receipts": {
            "artifact_binding": binding["content_id"],
            "exact_slice": receipt["content_id"],
        },
        "outputs": {
            "binding": binding_path.name,
            "exact_slice": receipt_path.name,
            "summary": summary_path.name,
        },
    }
    summary_path.write_bytes(canonical_bytes(summary) + b"\n")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=PROJECT_ROOT / "out" / "public-exact-slice",
    )
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.output_dir), sort_keys=True))
    except RehostError as exc:
        print(json.dumps(exc.as_dict(), sort_keys=True))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
