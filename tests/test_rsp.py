from __future__ import annotations

import unittest

from verirehost.rsp import packet


class RspPacketTests(unittest.TestCase):
    def test_packet_checksum(self) -> None:
        self.assertEqual(packet("p20"), b"$p20#d2")
        self.assertEqual(packet("c"), b"$c#63")


if __name__ == "__main__":
    unittest.main()
