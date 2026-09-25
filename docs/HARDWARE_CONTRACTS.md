# Temporal hardware contracts

Security-sensitive rehosting often reaches a point where exact firmware code
has been executed but the outcome still depends on a device, interconnect,
reset controller, or secure service. VeriRehost represents that boundary as a
contract rather than silently choosing the convenient hardware behavior.

## Five separable questions

A multi-boot experiment should not collapse these questions into one Boolean:

1. **admission:** does the environment deliver the request to the exact code?
2. **visibility:** when do device-written bytes become CPU-visible?
3. **reset:** what happens to active work and staged persistence?
4. **reentry:** which boot mode is selected after reset?
5. **irreversibility:** can a secure service program monotonic state?

The public primitives deliberately do not assign product meaning to any of
these questions. Private adapters bind them to exact artifacts and evidence.

## Logical time is not wall-clock time

`DeterministicScheduler` orders events by logical tick, phase, and insertion
sequence. The phases make device, DMA, coherence, interrupt, software, and
reset ordering explicit. They are an executable partial-order hypothesis, not
a claim about cycle counts or throughput.

Scheduling an earlier phase in the current tick is rejected as a causality
error. Event and state budgets fail closed.

## Split DMA views

`DmaTransfer` keeps a device view and a CPU view of a bounded leading window.
The complete request may be much larger than that window. Three declared
visibility policies are available:

- `packet`: received packet bytes immediately enter the CPU view;
- `completion`: device bytes enter the CPU view only at transfer completion;
- `explicit_sync`: software must explicitly synchronize the views.

Full-size packets do not complete a request unless they reach its declared
length. A short packet or zero-length packet completes it. Active-transfer
reset has its own explicit disposition; reset is never treated as an implicit
successful completion.

The descriptor-chain type validates contiguous coverage, hardware ownership,
chaining, and final-descriptor placement. Receipts contain payload digests,
never payload bytes.

## State across reset

`PlatformState` separates:

- volatile state;
- retention state;
- staged persistent values;
- committed persistent values;
- a requested next boot mode.

Each `ResetPolicy` declares whether retention survives, whether staged writes
are flushed, discarded, or retained, and whether a reentry request is honored.
The public model performs reset atomically; target adapters must disclose any
stronger timing or durability assumptions.

## Monotonic state

`MonotonicOtp` distinguishes `allow`, `deny`, and `unknown`. Unknown is not a
safe denial. Rules match explicit string context and may restrict the mask they
can program. Overlapping rules, bit clearing, and out-of-range masks fail
closed. OTP and fuse remain distinct side-effect classes.

The model can prove what a declared authorization policy does. It cannot turn
an inferred secure-monitor policy into physical fuse evidence.

## Three-valued policy matrices

`evaluate_contract_matrix` exhausts a finite Cartesian product of declared
policy variants. Every outcome is `true`, `false`, or `unknown`. The receipt
records:

- counts for all three values;
- whether the result is conclusive;
- whether success is possible or universal;
- variants shared by every successful row;
- axes that can change the outcome while other assignments remain fixed;
- deterministic first false and unknown counterexamples.

An unknown row is never promoted to success, failure, or safety. A result is
only conclusive over the variants actually declared by the caller.

## Evidence ceiling

These primitives can strengthen the implication:

> If the physical platform implements this contract, the exact downstream
> evidence has this result.

They cannot prove the antecedent. Closing that final gap requires authoritative
controller documentation, RTL, a hash-bound exact implementation, or a
physical measurement. Receipts preserve this ceiling even when every modeled
row has been exhausted.
