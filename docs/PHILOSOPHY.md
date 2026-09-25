# Philosophy: rehosting as an argument

Rehosting is not a screenshot of a serial console. It is an argument about causality:

1. these immutable bytes entered the experiment;
2. this original code or declared model evaluated them;
3. these environmental assumptions were supplied;
4. this state transition occurred;
5. the transition disappeared under a relevant negative control.

If one of those clauses is missing, the result may still be useful engineering, but it is not yet strong evidence.

## Selective fidelity

“Full-system” and “exact” are different axes. A large emulator can model many peripherals while replacing the one security decision that matters. A small harness can execute the exact decision routine while modeling everything around it.

This project therefore assigns fidelity to boundaries:

- **artifact fidelity:** which exact bytes were used;
- **code fidelity:** which instructions were executed rather than replaced;
- **state fidelity:** which registers, memory, and persistent values came from the target;
- **service fidelity:** which callees, devices, or secure-world services were modeled;
- **temporal fidelity:** which order, interrupts, retries, and resets were preserved.

A receipt can be exact on one boundary and modeled on another. It must say so.

## An adaptation is not a secret

Rehosting often requires patches, hooks, fixed return values, synthetic devices, or rebuilt components. These are legitimate research techniques. The failure is hiding them behind a broad claim such as “the firmware boots.”

Every adaptation belongs in one of three categories:

- **mechanical:** relocation, loader metadata, or an ABI bridge that should not change the decision;
- **environmental:** a peripheral or service model that supplies an expected dependency;
- **semantic:** a patch or hook capable of changing the security outcome.

Semantic adaptations demand a control showing that the conclusion does not merely restate the adaptation.

## Differential controls before conclusions

A useful control attacks the causal explanation, not the harness plumbing. A
straight-line slice should fail if its stop address changes, a digest binding
should fail when one input byte changes, and an address-reference test should
distinguish a real reference from a nearby unrelated instruction. The project
treats a control matrix as one artifact rather than selecting only a convenient
row.

## Bounded execution

Exact-binary execution is not permission to emulate indefinitely. Engines should declare:

- entry and permitted exit addresses;
- mapped ranges and permissions;
- instruction, wall-clock, and allocation budgets;
- permitted service hooks;
- MMIO behavior, with unknown accesses failing closed;
- nondeterminism sources and seeds;
- the executed basic-block or address transcript.

This makes hangs, accidental fall-through, and unexplained environment dependencies observable.

## Receipts, not mythology

Receipts are deterministic descriptions of what happened. They are content-addressed after canonical JSON serialization. Timestamps, workstation paths, usernames, and other ambient state stay outside the signed material unless the experiment genuinely depends on them.

The receipt is not automatically true; it is inspectable. Its job is to prevent a conclusion from drifting away from its inputs, controls, and model boundary.

## Safe publication

Reproducibility does not require shipping proprietary firmware or private
target integrations. This repository publishes the generic harness, schemas,
synthetic controls, and claim discipline. Researchers privately bind lawfully
obtained artifacts. Target-specific conclusions and reproduction material stay
outside the public framework unless a separate disclosure process authorizes
their release.
