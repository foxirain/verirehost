# Contributing

Contributions should make the evidence stronger, not merely make a scenario pass.

Before proposing a change:

1. Run `make check` on Python 3.11 or newer.
2. Add a negative control for every newly modeled success path.
3. Record every adaptation that changes executed code, memory, peripherals, policy, or timing.
4. Keep proprietary inputs outside the repository and identify them only by digest and size.
5. State the highest claim grade the change actually supports.

A backend is not “exact” because it consumes a real blob. Exact-binary claims require an immutable input hash, architecture and load assumptions, a bounded executed address set, hook transcripts, and tests showing that the same observation disappears under the relevant hardened control.

Commits should be small enough to audit. Tests may use only redistributable fixtures.
