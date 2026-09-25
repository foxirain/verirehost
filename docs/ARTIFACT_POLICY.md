# Artifact policy

## Repository-safe artifacts

- original source and documentation;
- deliberately incompatible synthetic containers and manifests;
- test configurations and tiny generated fixtures;
- SHA-256 digests, byte lengths, build identifiers, and redistribution flags;
- redacted receipts without local paths or secrets.

## Private-only artifacts

- vendor firmware packages and extracted binaries;
- partition images, DTBs, kernels, modules, and secure-world components unless their license explicitly permits redistribution;
- keys, certificates not already public, device identifiers, and service credentials;
- proprietary symbol maps or leaked materials.

Private inputs live under ignored `private/` or `vendor/` paths. A local binding file may map a profile role to a path, but that file is never embedded in a receipt.

## Receipt representation

Each artifact record should contain:

- stable role;
- SHA-256 digest;
- byte length;
- format or architecture when known;
- redistribution status;
- derivation digest for generated artifacts.

Absolute paths, usernames, timestamps unrelated to semantics, and host-specific inode metadata are excluded so receipts remain comparable across laboratories.
