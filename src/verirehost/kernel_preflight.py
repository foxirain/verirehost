from __future__ import annotations

from pathlib import Path
from typing import Any

from . import __version__
from .canonical import sha256_bytes
from .receipt import seal


REQUIRED = {
    "arm64": [["CONFIG_ARM64=y"]],
    "pl011_console": [["CONFIG_SERIAL_AMBA_PL011=y", "CONFIG_SERIAL_AMBA_PL011_CONSOLE=y"]],
    "generic_pci": [["CONFIG_PCI=y", "CONFIG_PCI_HOST_GENERIC=y"]],
    "xhci": [["CONFIG_USB_XHCI_HCD=y"], ["CONFIG_USB_XHCI_PCI=y"]],
    "usb_mass_storage": [["CONFIG_SCSI=y", "CONFIG_BLK_DEV_SD=y", "CONFIG_USB_STORAGE=y"]],
    "ext4": [["CONFIG_EXT4_FS=y"]],
}


def parse_config(raw: bytes) -> set[str]:
    enabled: set[str] = set()
    for line in raw.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if line.startswith("CONFIG_") and "=" in line:
            enabled.add(line)
    return enabled


def inspect(config_path: Path, target: dict[str, Any] | None = None) -> dict[str, Any]:
    raw = config_path.read_bytes()
    enabled = parse_config(raw)
    checks = []
    passed = True
    for capability, clauses in REQUIRED.items():
        clause_results = []
        for clause in clauses:
            missing = [item for item in clause if item not in enabled]
            clause_results.append({"required": clause, "missing": missing, "passed": not missing})
        capability_passed = all(item["passed"] for item in clause_results)
        passed &= capability_passed
        checks.append({"capability": capability, "passed": capability_passed, "clauses": clause_results})

    virtio_blk = any(value.startswith("CONFIG_VIRTIO_BLK=") for value in enabled)
    return seal(
        {
            "kind": "kernel_static_preflight",
            "tool": {"name": "verirehost", "version": __version__},
            "target": target or {"family": "unspecified"},
            "claim_grade": "static_artifact",
            "status": "compatible" if passed else "incompatible",
            "input": {"role": "kernel_config", "sha256": sha256_bytes(raw), "size": len(raw)},
            "candidate_transport": "qemu-virt + PCI xHCI + USB mass storage + ext4",
            "checks": checks,
            "observations": {
                "virtio_blk_enabled": virtio_blk,
                "virtio_blk_required": False,
                "reason": "the selected storage lane uses xHCI/USB rather than virtio-blk",
            },
            "model_boundary": {
                "executed": ["Kconfig parser and capability predicates"],
                "modeled": ["QEMU virt PCI topology and boot handoff"],
                "not_claimed": ["kernel boot success", "driver probe success", "physical-device behavior"],
            },
            "adaptations": ["static configuration evidence only; no kernel code was executed"],
        }
    )
