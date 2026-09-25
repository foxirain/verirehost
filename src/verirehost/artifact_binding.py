from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .canonical import sha256_bytes
from .errors import RehostError
from .receipt import seal


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def bind(profile: dict[str, Any], profile_bytes: bytes, role: str, path: Path) -> dict[str, Any]:
    artifacts = profile.get("artifacts")
    if not isinstance(artifacts, dict) or role not in artifacts:
        raise RehostError("ARTIFACT_ROLE", "profile does not declare this artifact role", {"role": role})
    expected = artifacts[role]
    actual_digest, actual_size = _hash_file(path)
    digest_match = actual_digest == expected["sha256"]
    size_match = actual_size == expected["size"]
    matched = digest_match and size_match

    return seal(
        {
            "kind": "artifact_binding",
            "tool": {"name": "verirehost", "version": "0.1.0"},
            "profile_id": profile["id"],
            "target": profile["target"],
            "claim_grade": "static_artifact",
            "status": "matched" if matched else "mismatch",
            "profile": {"sha256": sha256_bytes(profile_bytes), "size": len(profile_bytes)},
            "artifact": {
                "role": role,
                "expected": {
                    "sha256": expected["sha256"],
                    "size": expected["size"],
                    "redistributable": expected.get("redistributable", False),
                },
                "observed": {"sha256": actual_digest, "size": actual_size},
                "digest_match": digest_match,
                "size_match": size_match,
            },
            "claims": (
                [
                    {
                        "id": f"artifact-{role}-bound",
                        "statement": "The locally supplied bytes match the profile's expected digest and size.",
                        "grade": "static_artifact",
                    }
                ]
                if matched
                else []
            ),
            "model_boundary": {
                "executed": ["streaming SHA-256 and byte count"],
                "modeled": [],
                "not_claimed": ["artifact provenance", "redistribution rights", "target execution"],
            },
            "adaptations": ["the local filesystem path is intentionally excluded from the sealed receipt"],
        }
    )
