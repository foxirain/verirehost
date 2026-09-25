# VeriRehost

VeriRehost is an evidence-first framework for small, bounded firmware
rehosting experiments. It is intentionally a framework rather than a device
case study: the public tree contains generic execution, artifact-binding,
receipt, static-analysis, and preflight primitives, but no target-specific
trust-chain conclusions or vulnerability research.

The central question is:

> What is the smallest amount of original code and explicit environment
> modeling needed to support a narrowly worded observation?

## Public scope

The repository provides:

- content-addressed, path-free experiment receipts;
- profiles that bind private artifacts by SHA-256 and byte length;
- a fail-closed AArch64 exact-slice runner with instruction and memory bounds;
- AArch64 reference-discovery helpers;
- deterministic bounded state-space exploration with shortest witnesses;
- a small GDB Remote Serial Protocol client for supervised rehosts;
- static kernel-configuration preflight for a generic QEMU USB lane;
- synthetic tests that contain no vendor firmware, target addresses, or device
  protocol details.

The public tree does **not** contain device-specific addresses, build analyses,
boot-chain verdicts, race schedules, transport framing, write automation,
patch offsets, or vulnerability reproduction material. Those belong in a
separate private research layer and, when appropriate, a coordinated
disclosure process.

## Design rules

1. **Exactness is local.** A claim names the exact artifact, address range,
   services, and adaptations that produced it.
2. **Unknown behavior fails closed.** Undeclared code, memory, MMIO, and
   services terminate a run.
3. **Receipts precede prose.** Inputs and model boundaries are sealed before a
   conclusion is written.
4. **Private paths stay private.** Receipts contain digests and sizes, never
   workstation paths or proprietary bytes.
5. **Rehosting is not hardware proof.** Emulated execution cannot inherit a
   physical-device claim.

## Quick start

```bash
python -m venv .venv
.venv/bin/pip install -e '.[exact]'
make check PYTHON=.venv/bin/python
```

Validate generic experiment metadata:

```bash
.venv/bin/python -m verirehost validate-profile \
  profiles/synthetic-slice.example.json
```

Bind a locally obtained private artifact without putting its path in the
receipt:

```bash
.venv/bin/python -m verirehost bind-artifact \
  profiles/local.example.json firmware private/firmware.bin \
  --output out/binding.json
```

Run a bounded straight AArch64 slice:

```bash
.venv/bin/python -m verirehost run-exact-slice \
  private/firmware.bin \
  --target-id local-lab-target \
  --image-base 0x02000000 \
  --entry 0x02001000 \
  --stop-exclusive 0x02001020 \
  --stack-base 0x0ff00000 \
  --register x0=0 \
  --output out/exact-slice.json
```

The generic runner exposes no service hooks, storage backend, transport, or
MMIO model. A branch outside the declared interval is an error.

Run a static kernel transport preflight:

```bash
.venv/bin/python -m verirehost preflight-kernel \
  fixtures/synthetic/qemu-usb-ready.config \
  --model synthetic-arm64 --build lab-v1 \
  --output out/preflight/kernel.json
```

Explore every reachable state in a target-neutral synthetic model:

```bash
.venv/bin/python -m verirehost explore-state-space \
  profiles/synthetic-state-space.example.json \
  --output out/state-space/synthetic.json
```

The resulting receipt distinguishes an exhausted state space from a depth or
state-budget stop. An unreached goal is never treated as impossible after an
incomplete search.

## Claim grades

| Grade | Meaning |
|---|---|
| `static_artifact` | Immutable bytes were parsed or searched. |
| `synthetic_model` | Only public laboratory state and fixtures executed. |
| `exact_binary_slice` | Hash-bound target instructions executed inside declared bounds. |
| `exact_binary_slice_with_service_model` | The exact slice used explicitly modeled external services. |
| `exact_artifact_host_cryptographic_check` | A public algorithm was evaluated over exact private artifacts on the host. |
| `compatible_kernel` | A rebuilt or adapted kernel executed under declared conditions. |
| `exact_kernel` | A hash-bound shipping kernel produced the observation in a rehost. |
| `physical_device` | A recoverable instrumented device produced the observation. |

Higher grades do not erase assumptions at lower boundaries. See
[Claim discipline](docs/CLAIMS.md) and [Architecture](docs/ARCHITECTURE.md).

## Publication boundary

This repository is not a flashing, unlocking, or exploitation toolkit. It
ships no proprietary firmware, device transport, ready-to-deploy image,
target-specific finding, or physical-write workflow. Read
[SECURITY.md](SECURITY.md) and the [artifact policy](docs/ARTIFACT_POLICY.md)
before adding a backend.

Licensed under Apache-2.0.
