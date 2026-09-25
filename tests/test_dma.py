from __future__ import annotations

import unittest

from verirehost.dma import (
    DmaDescriptor,
    DmaDescriptorChain,
    DmaTransfer,
    ResetDisposition,
    TransferState,
    VisibilityPolicy,
)
from verirehost.errors import RehostError
from verirehost.receipt import verify


def chain(length: int) -> DmaDescriptorChain:
    first = length - 64
    return DmaDescriptorChain(
        (
            DmaDescriptor(offset=0, length=first, chained=True),
            DmaDescriptor(
                offset=first,
                length=64,
                interrupt_on_completion=True,
                last=True,
            ),
        )
    )


def transfer(policy: VisibilityPolicy) -> DmaTransfer:
    return DmaTransfer(
        transfer_id="synthetic-out",
        declared_length=256,
        maximum_packet_size=64,
        initial_window=b"S" * 128,
        visibility=policy,
        descriptors=chain(256),
    )


class DmaTransferTests(unittest.TestCase):
    def test_packet_policy_exposes_bytes_before_completion(self) -> None:
        subject = transfer(VisibilityPolicy.PACKET)
        subject.submit_packet(b"A" * 64, tick=1)
        subject.submit_packet(b"B" * 64, tick=2)
        self.assertTrue(subject.active)
        self.assertEqual(subject.observe_cpu(tick=3), b"A" * 64 + b"B" * 64)

    def test_completion_policy_keeps_stock_cpu_view_while_active(self) -> None:
        subject = transfer(VisibilityPolicy.COMPLETION)
        subject.submit_packet(b"A" * 64, tick=1)
        subject.submit_packet(b"B" * 64, tick=2)
        self.assertEqual(subject.device_window, b"A" * 64 + b"B" * 64)
        self.assertEqual(subject.observe_cpu(tick=3), b"S" * 128)
        subject.submit_packet(b"C" * 64, tick=4)
        subject.submit_packet(b"D" * 64, tick=5)
        self.assertEqual(subject.state, TransferState.COMPLETED)
        self.assertEqual(subject.cpu_window, b"A" * 64 + b"B" * 64)

    def test_explicit_sync_is_distinct_from_packet_and_completion(self) -> None:
        subject = transfer(VisibilityPolicy.EXPLICIT_SYNC)
        subject.submit_packet(b"A" * 64, tick=1)
        self.assertEqual(subject.cpu_window[:64], b"S" * 64)
        subject.sync_for_cpu(tick=2)
        self.assertEqual(subject.cpu_window[:64], b"A" * 64)

        completed = transfer(VisibilityPolicy.EXPLICIT_SYNC)
        for tick, byte in enumerate((b"A", b"B", b"C", b"D"), start=1):
            completed.submit_packet(byte * 64, tick=tick)
        self.assertEqual(completed.state, TransferState.COMPLETED)
        self.assertEqual(completed.cpu_window, b"S" * 128)
        completed.sync_for_cpu(tick=5)
        self.assertEqual(completed.cpu_window, b"A" * 64 + b"B" * 64)

    def test_full_packets_without_zlp_remain_active(self) -> None:
        subject = transfer(VisibilityPolicy.PACKET)
        subject.submit_packet(b"A" * 64, tick=1)
        subject.submit_packet(b"B" * 64, tick=2)
        self.assertTrue(subject.active)
        self.assertEqual(subject.received_length, 128)

    def test_short_packet_completes(self) -> None:
        subject = transfer(VisibilityPolicy.PACKET)
        subject.submit_packet(b"A" * 63, tick=1)
        self.assertEqual(subject.state, TransferState.COMPLETED)

    def test_reset_dispositions_are_observable(self) -> None:
        blocked = transfer(VisibilityPolicy.PACKET)
        blocked.submit_packet(b"A" * 64, tick=1)
        with self.assertRaises(RehostError) as raised:
            blocked.reset(tick=2, disposition=ResetDisposition.FAIL_IF_ACTIVE)
        self.assertEqual(raised.exception.code, "DMA_RESET_ACTIVE")

        committed = transfer(VisibilityPolicy.COMPLETION)
        committed.submit_packet(b"A" * 64, tick=1)
        committed.reset(tick=2, disposition=ResetDisposition.COMMIT_DEVICE_VISIBLE)
        self.assertEqual(committed.cpu_window[:64], b"A" * 64)

        discarded = transfer(VisibilityPolicy.COMPLETION)
        discarded.submit_packet(b"A" * 64, tick=1)
        discarded.reset(tick=2, disposition=ResetDisposition.DISCARD_UNCOMMITTED)
        self.assertEqual(discarded.device_window, b"S" * 128)

    def test_receipt_is_sealed_and_payload_free(self) -> None:
        subject = transfer(VisibilityPolicy.PACKET)
        subject.submit_packet(b"A" * 64, tick=1)
        receipt = subject.receipt(model_id="synthetic-dma")
        verify(receipt)
        self.assertNotIn("A" * 32, str(receipt))
        self.assertEqual(receipt["result"]["state"], "active")

    def test_descriptor_chain_rejects_gaps(self) -> None:
        with self.assertRaises(ValueError):
            DmaDescriptorChain(
                (
                    DmaDescriptor(offset=0, length=64, chained=True),
                    DmaDescriptor(offset=65, length=64, last=True),
                )
            )

    def test_invalid_ticks_and_observation_lengths_fail_closed(self) -> None:
        subject = transfer(VisibilityPolicy.PACKET)
        with self.assertRaises(RehostError) as tick:
            subject.submit_packet(b"A" * 64, tick=-1)
        self.assertEqual(tick.exception.code, "DMA_TICK")
        with self.assertRaises(RehostError) as length:
            subject.observe_cpu(tick=0, length=-1)
        self.assertEqual(length.exception.code, "DMA_OBSERVE")


if __name__ == "__main__":
    unittest.main()
