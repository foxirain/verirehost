from __future__ import annotations

import unittest

from verirehost.platform_state import (
    PersistentDisposition,
    PlatformState,
    ResetPolicy,
)
from verirehost.receipt import verify


class PlatformStateTests(unittest.TestCase):
    def test_reset_domains_and_reentry_are_explicit(self) -> None:
        subject = PlatformState(default_boot_mode="normal")
        subject.set_volatile("parser", "receiving")
        subject.set_retention("reason", "synthetic")
        subject.stage_persistent("record", {"digest": "abc"})
        subject.request_reentry("service")
        policy = ResetPolicy(
            "synthetic-safe-reset",
            preserve_retention=True,
            persistent_disposition=PersistentDisposition.FLUSH_STAGED,
            honor_reentry_request=True,
        )
        self.assertEqual(subject.reset(reason="requested", policy=policy), "service")
        snapshot = subject.snapshot()
        self.assertEqual(snapshot["volatile"], {})
        self.assertEqual(snapshot["retention"], {"reason": "synthetic"})
        self.assertEqual(snapshot["persistent_committed"]["record"], {"digest": "abc"})
        self.assertEqual(snapshot["boot_count"], 2)
        verify(subject.receipt(model_id="synthetic-reset", policies=[policy]))

    def test_discard_and_denied_reentry_fail_closed(self) -> None:
        subject = PlatformState(default_boot_mode="normal")
        subject.stage_persistent("record", "candidate")
        subject.request_reentry("service")
        policy = ResetPolicy(
            "synthetic-discard",
            preserve_retention=False,
            persistent_disposition=PersistentDisposition.DISCARD_STAGED,
            honor_reentry_request=False,
        )
        self.assertEqual(subject.reset(reason="requested", policy=policy), "normal")
        self.assertEqual(subject.committed, {})
        self.assertEqual(subject.staged, {})

    def test_preserve_staged_does_not_claim_durability(self) -> None:
        subject = PlatformState()
        subject.stage_persistent("record", "pending")
        policy = ResetPolicy(
            "synthetic-pending",
            preserve_retention=False,
            persistent_disposition=PersistentDisposition.PRESERVE_STAGED,
            honor_reentry_request=False,
        )
        subject.reset(reason="requested", policy=policy)
        self.assertEqual(subject.staged, {"record": "pending"})
        self.assertEqual(subject.committed, {})


if __name__ == "__main__":
    unittest.main()
