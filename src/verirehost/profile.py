from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .errors import RehostError


PROFILE_SCHEMA = "verirehost/profile/v1"
CLAIM_GRADES = {
    "static_artifact",
    "synthetic_model",
    "exact_binary_slice",
    "exact_binary_slice_with_service_model",
    "exact_artifact_host_cryptographic_check",
    "compatible_kernel",
    "exact_kernel",
    "physical_device",
}


def load(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    try:
        profile = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RehostError("PROFILE_JSON", "profile is not valid UTF-8 JSON", {"path": str(path)}) from exc
    validate(profile)
    return profile, raw


def validate(profile: Any) -> None:
    if not isinstance(profile, dict) or profile.get("schema") != PROFILE_SCHEMA:
        raise RehostError("PROFILE_SCHEMA", "unsupported profile schema")
    for field in ("id", "target", "claim_grade", "adaptations"):
        if field not in profile:
            raise RehostError("PROFILE_FIELD", "required profile field is missing", {"field": field})
    if not isinstance(profile["id"], str) or not profile["id"]:
        raise RehostError("PROFILE_ID", "profile id must be a non-empty string")
    if profile["claim_grade"] not in CLAIM_GRADES:
        raise RehostError("PROFILE_GRADE", "unknown claim grade", {"grade": profile["claim_grade"]})
    if not isinstance(profile["target"], dict):
        raise RehostError("PROFILE_TARGET", "target must be an object")
    if not isinstance(profile["adaptations"], list) or not all(
        isinstance(value, str) and value for value in profile["adaptations"]
    ):
        raise RehostError("PROFILE_ADAPTATIONS", "adaptations must be a list of non-empty strings")

    artifacts = profile.get("artifacts", {})
    if not isinstance(artifacts, dict):
        raise RehostError("PROFILE_ARTIFACTS", "artifacts must be an object keyed by role")
    for role, artifact in artifacts.items():
        if not isinstance(role, str) or not isinstance(artifact, dict):
            raise RehostError("PROFILE_ARTIFACTS", "artifact declarations must be objects keyed by role")
        digest = artifact.get("sha256")
        size = artifact.get("size")
        if not isinstance(digest, str) or len(digest) != 64 or not isinstance(size, int) or size <= 0:
            raise RehostError("PROFILE_ARTIFACTS", "artifact requires a SHA-256 digest and positive size", {"role": role})
        try:
            bytes.fromhex(digest)
        except ValueError as exc:
            raise RehostError("PROFILE_ARTIFACTS", "artifact digest is not hexadecimal", {"role": role}) from exc
