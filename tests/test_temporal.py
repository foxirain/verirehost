from __future__ import annotations

import unittest

from verirehost.errors import RehostError
from verirehost.temporal import DeterministicScheduler, EventPhase


class DeterministicSchedulerTests(unittest.TestCase):
    def test_orders_tick_phase_and_insertion(self) -> None:
        scheduler = DeterministicScheduler()
        scheduler.schedule_at(2, EventPhase.SOFTWARE, "later", lambda _scheduler: None)
        scheduler.schedule_at(1, EventPhase.DMA, "dma", lambda _scheduler: {"value": 1})
        scheduler.schedule_at(1, EventPhase.DEVICE, "device", lambda _scheduler: None)
        scheduler.schedule_at(1, EventPhase.DMA, "dma-second", lambda _scheduler: None)
        trace = scheduler.run()
        self.assertEqual(
            [event["name"] for event in trace],
            ["device", "dma", "dma-second", "later"],
        )
        self.assertEqual(trace[1]["details"], {"value": 1})
        self.assertEqual(scheduler.summary()["events_pending"], 0)

    def test_callback_can_schedule_later_phase_same_tick(self) -> None:
        scheduler = DeterministicScheduler()

        def device(current: DeterministicScheduler) -> None:
            current.schedule_at(
                current.now,
                EventPhase.INTERRUPT,
                "interrupt",
                lambda _scheduler: None,
            )

        scheduler.schedule_at(1, EventPhase.DEVICE, "device", device)
        self.assertEqual(
            [event["name"] for event in scheduler.run()],
            ["device", "interrupt"],
        )

    def test_rejects_same_tick_backward_phase(self) -> None:
        scheduler = DeterministicScheduler()

        def software(current: DeterministicScheduler) -> None:
            current.schedule_at(current.now, EventPhase.DMA, "backwards", lambda _: None)

        scheduler.schedule_at(1, EventPhase.SOFTWARE, "software", software)
        with self.assertRaises(RehostError) as raised:
            scheduler.run()
        self.assertEqual(raised.exception.code, "TIME_CAUSALITY")

    def test_budget_fails_closed(self) -> None:
        scheduler = DeterministicScheduler(max_events=1)
        scheduler.schedule_at(1, EventPhase.DEVICE, "one", lambda _: None)
        scheduler.schedule_at(2, EventPhase.DEVICE, "two", lambda _: None)
        with self.assertRaises(RehostError) as raised:
            scheduler.run()
        self.assertEqual(raised.exception.code, "TIME_BUDGET")


if __name__ == "__main__":
    unittest.main()
