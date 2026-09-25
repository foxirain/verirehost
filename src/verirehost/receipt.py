from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, sha256_object
from .errors import RehostError


RECEIPT_SCHEMA = "verirehost/receipt/v1"


def seal(body: dict[str, Any]) -> dict[str, Any]:
    if "content_id" in body:
        raise RehostError("RECEIPT_FIELD", "unsealed receipt body must not contain content_id")
    material = {"schema": RECEIPT_SCHEMA, **body}
    return {**material, "content_id": f"sha256:{sha256_object(material)}"}


def verify(receipt: dict[str, Any]) -> None:
    if receipt.get("schema") != RECEIPT_SCHEMA:
        raise RehostError("RECEIPT_SCHEMA", "unsupported receipt schema")
    claimed = receipt.get("content_id")
    if not isinstance(claimed, str) or not claimed.startswith("sha256:"):
        raise RehostError("RECEIPT_ID", "receipt has no valid content id")
    material = {key: value for key, value in receipt.items() if key != "content_id"}
    actual = f"sha256:{sha256_object(material)}"
    if actual != claimed:
        raise RehostError(
            "RECEIPT_TAMPERED",
            "receipt content does not match its content id",
            {"claimed": claimed, "actual": actual},
        )


def write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value) + b"\n")


def read(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RehostError("RECEIPT_READ", "unable to read receipt", {"path": str(path)}) from exc
    if not isinstance(value, dict):
        raise RehostError("RECEIPT_TYPE", "receipt must be a JSON object")
    return value
