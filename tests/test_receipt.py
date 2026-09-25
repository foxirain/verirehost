from __future__ import annotations

import unittest

from verirehost.errors import RehostError
from verirehost.receipt import seal, verify


class ReceiptTests(unittest.TestCase):
    def test_sealed_receipt_verifies_and_detects_mutation(self) -> None:
        receipt = seal(
            {
                "kind": "test",
                "tool": {"name": "verirehost", "version": "0.1.0"},
                "status": "successful",
            }
        )
        verify(receipt)
        receipt["status"] = "stopped"
        with self.assertRaisesRegex(RehostError, "RECEIPT_TAMPERED"):
            verify(receipt)

    def test_key_order_does_not_change_content_id(self) -> None:
        first = seal({"kind": "test", "tool": {"name": "verirehost", "version": "0.1.0"}, "a": 1})
        second = seal({"a": 1, "tool": {"version": "0.1.0", "name": "verirehost"}, "kind": "test"})
        self.assertEqual(first["content_id"], second["content_id"])


if __name__ == "__main__":
    unittest.main()
