# Architecture

VeriRehost is a collection of narrow experiment primitives. It does
not claim to emulate a complete SoC or product.

```text
private artifact ── digest/size binding ─┐
                                        ├─ sealed receipt ── claim review
public profile ─── declared boundaries ─┤
                                        │
bounded engine ─── trace digests ───────┘
```

## Artifact binding

A local artifact is accepted only when its SHA-256 digest and byte length match
the public profile. The sealed receipt records identity metadata but excludes
the local path and artifact bytes.

## Exact-slice lane

The public exact runner maps one private AArch64 image read/execute and one
bounded stack read/write. It accepts explicit initial registers, permits only a
single declared code interval, and stops after a fixed instruction and time
budget. Execution outside the interval, unknown memory, and engine failures are
errors.

The runner records:

- artifact digest and length;
- image, entry, stop, and stack layout;
- instruction budget and observed count;
- digests of executed addresses and instruction bytes;
- final values of the explicitly initialized registers.

It intentionally exposes no public service hook, MMIO model, storage backend,
transport, or device integration. Target-specific service models belong in a
private research layer.

## Static-analysis lane

The AArch64 helper library locates direct branches and common address-building
references without imposing target semantics. Static observations receive a
`static_artifact` grade; finding an instruction or reference is not execution
evidence.

## Typed SMC service-model lane

The public SMC router gives private exact-slice integrations an explicit
boundary for secure-monitor calls. A backend matches a declared function-ID
mask, advertises every kind of side effect it can model, and returns a typed
register response. Unknown IDs, overlapping matches, and undeclared effects
fail closed. OTP and fuse effects are distinct capabilities so that a generic
success return cannot silently stand in for irreversible hardware state.

The router receipt is a `synthetic_model` record. It proves routing and
capability enforcement in the declared model only; it does not promote a
modeled secure service to exact firmware or physical-device evidence.

## Kernel-preflight lane

The preflight command evaluates a kernel configuration for a generic QEMU PCI
xHCI and USB-mass-storage lane. It emits static capability evidence only. A
compatible configuration is not evidence that a kernel booted.

## Deterministic state-space lane

The state-space explorer executes target-neutral transition declarations over
sets of uninterpreted atoms. Breadth-first search records the shortest witness
for each reached goal or forbidden predicate. Transition order is normalized,
states are deduplicated, and depth/state budget exhaustion is explicit.

The scheduler proves reachability only inside the declared abstract model. It
does not establish that an atom corresponds to real DMA visibility, timing,
reset, firmware, or hardware behavior. Product semantics and exact evidence
bindings remain in the private integration layer.

## Receipt layer

Receipts use canonical JSON and a content ID computed over all material fields.
Verification detects mutation after sealing. A valid content ID proves
integrity of the record, not correctness of the experimenter's model.

## Trust boundaries

| Boundary | Trusted for | Not trusted for |
|---|---|---|
| Public synthetic inputs | Parser and orchestration tests | Vendor behavior |
| Private artifact binding | Digest and length identity | Provenance or redistribution rights |
| Exact-slice engine | Instructions inside the declared interval | Whole-firmware or device behavior |
| Typed SMC router | Unique dispatch and declared modeled effects | Vendor monitor logic or physical OTP/fuse state |
| Kernel preflight | Static configuration capability | Successful boot or driver behavior |
| Deterministic state-space explorer | Reachability within declared transitions | Physical scheduling, timing, DMA, or reset behavior |
| Receipt content ID | Detecting post-seal mutation | Truth of assumptions or security impact |

## Private integration boundary

Profiles or backends containing product identifiers, build-specific addresses,
service semantics, protocol framing, race schedules, write paths, or security
conclusions are outside the public architecture. Public additions should remain
usable with synthetic inputs and should not encode the result of a private
target investigation.
