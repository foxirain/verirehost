# Security and research-safety policy

VeriRehost is a defensive research instrument. Its public tree contains
only generic rehosting infrastructure and synthetic controls.

## Public-tree boundary

The repository accepts:

- synthetic fixtures that are deliberately incompatible with vendor wire formats;
- hashes and redistribution-safe metadata for private artifacts;
- parsers, state machines, engine contracts, receipts, and negative controls;
- non-destructive markers whose only side effect is evidence emission.

The repository does not accept:

- proprietary vendor firmware, keys, certificates, or leaked source;
- ready-to-flash images, transport automation, unlock bypass scripts, or persistence payloads;
- secrets, device identifiers, or absolute paths from a researcher workstation;
- claims of physical-device success supported only by synthetic or emulated evidence.

Private firmware belongs under ignored `private/` or `vendor/` directories. A public receipt may contain its SHA-256 digest, byte length, and role, but never its contents or local absolute path.

## Safe experiment defaults

- Storage backends must be snapshots, copies, or explicitly disposable images.
- Exact-binary engines must impose memory and instruction budgets.
- Unknown MMIO is fail-closed unless a profile explicitly models it.
- A run must retain its negative controls and adaptation list.
- Physical-device writes are outside this repository's automated workflows.

## Reporting a vulnerability in this project

Do not open a public issue for a vulnerability that could expose private firmware or create an immediately usable device-compromise path. After publication, contact the maintainers through the repository's private security-advisory channel.

## Publication stop rule

All target-specific investigation stays outside this public repository,
including blocked paths, negative findings, build identifiers, address maps,
unredacted traces, trust-chain conclusions, and vulnerability reproduction
material. Coordinated disclosure may later authorize a separate report, but it
does not change the generic-only boundary of this framework repository.
