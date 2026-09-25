# Claim discipline

Every externally visible conclusion should name a claim grade and cite one or more receipt content IDs.

## Grades

### `static_artifact`

Bytes were parsed or searched, but target code did not execute. Appropriate language: “the hashed artifact contains,” “the configuration enables,” or “the disassembly indicates.”

### `synthetic_model`

Only public laboratory code and fixtures executed. Appropriate language names
the exact modeled transition. This grade cannot establish firmware or device
behavior.

### `exact_binary_slice`

Machine code from a hashed target artifact executed within declared ranges. Appropriate language names the routine or slice and every service model that influenced it. It does not establish full boot or board behavior.

### `exact_binary_slice_with_service_model`

The same target-code standard as `exact_binary_slice`, but one or more typed
external services influenced the result. The claim must name those services
and separate target decisions from modeled side effects. A modeled external
call establishes only its declared arguments and return at that boundary—not
the behavior of a physical service.

### `exact_artifact_host_cryptographic_check`

An immutable target artifact was parsed and evaluated with a public algorithm
on the host. This can establish descriptor coverage and digest equality. It is
not execution of the target's verifier, key policy, or secure-world service.

### `compatible_kernel`

A rebuilt or patched kernel executed. This may validate interfaces, storage choices, or marker mechanics. It is not evidence that the shipping kernel accepts the same handoff.

### `exact_kernel`

The hashed shipping kernel executed in the rehost and produced the named observation. The claim remains limited by the virtual devices, boot protocol, DTB, command line, and policy adaptations.

### `physical_device`

An instrumented, recoverable device running the exact build produced the observation. The receipt must record reset/recovery conditions and distinguish a transient marker from persistence.

### `cross_receipt_composition`

Multiple independently sealed receipts were integrity-checked and joined by
target identity plus explicit control outcomes. This grade may close a path or
identify a proof gap, but it never promotes any input above its own evidence
grade and never implies monolithic execution.

## Forbidden promotions

- A real firmware input does not promote a synthetic parser to `exact_binary_slice`.
- A compatible kernel does not become exact because its configuration originated from the target.
- A physical boot-state screenshot does not establish how that state was reached.
- A diagnostic marker does not establish persistence, production safety, or any unrelated property.
- A result without its relevant negative control is provisional.
- A cross-receipt verdict cannot turn a modeled service into physical-device evidence.

## Suggested wording

Prefer:

> Receipt `sha256:…` shows that the hash-bound AArch64 slice reached its
> declared exclusive stop under the listed initial-register and stack model.
> No peripheral or physical device was executed.

Avoid:

> The firmware behaves this way on the product.

The second sentence collapses multiple unproven boundaries and implies an operational result the evidence may not support.
