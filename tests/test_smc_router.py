from __future__ import annotations

import unittest

from verirehost.errors import RehostError
from verirehost.receipt import verify
from verirehost.smc_router import (
    SideEffect,
    SmcBackend,
    SmcCall,
    SmcResponse,
    SmcRouter,
)


MASK64 = (1 << 64) - 1


class SmcRouterTests(unittest.TestCase):
    def test_routes_exact_service_and_seals_effects(self) -> None:
        def handler(call: SmcCall) -> SmcResponse:
            self.assertEqual(call.registers, (0x82000010, 7, 9))
            return SmcResponse(
                registers=(0, 7, 10),
                effects=frozenset({SideEffect.VOLATILE_STATE}),
            )

        router = SmcRouter(
            [
                SmcBackend(
                    name="synthetic-state-service",
                    mask=MASK64,
                    value=0x82000010,
                    capabilities=frozenset({SideEffect.VOLATILE_STATE}),
                    handler=handler,
                )
            ]
        )
        response = router.dispatch(
            SmcCall.from_registers(0x1000, x0=0x82000010, x1=7, x2=9)
        )
        self.assertEqual(response.registers, (0, 7, 10))
        receipt = router.receipt(
            target={"id": "synthetic-control", "architecture": "aarch64"},
            model_id="unit-test",
        )
        verify(receipt)
        self.assertEqual(receipt["observed_side_effects"], ["volatile_state"])
        self.assertNotIn("otp", receipt["observed_side_effects"])

    def test_unknown_service_fails_closed_and_is_audited(self) -> None:
        router = SmcRouter([])
        with self.assertRaises(RehostError) as raised:
            router.dispatch(SmcCall.from_registers(0x2000, x0=0xC2000010))
        self.assertEqual(raised.exception.code, "SMC_UNMODELED")
        self.assertEqual(router.events[0]["status"], "unmodeled")

    def test_overlapping_backends_fail_closed(self) -> None:
        def response(_call: SmcCall) -> SmcResponse:
            return SmcResponse(registers=(0,))

        router = SmcRouter(
            [
                SmcBackend("owner", 0xFF000000, 0x82000000, frozenset(), response),
                SmcBackend("function", MASK64, 0x82000010, frozenset(), response),
            ]
        )
        with self.assertRaises(RehostError) as raised:
            router.dispatch(SmcCall.from_registers(0x3000, x0=0x82000010))
        self.assertEqual(raised.exception.code, "SMC_AMBIGUOUS")

    def test_backend_cannot_hide_undeclared_fuse_effect(self) -> None:
        def handler(_call: SmcCall) -> SmcResponse:
            return SmcResponse(registers=(0,), effects=frozenset({SideEffect.FUSE}))

        router = SmcRouter(
            [SmcBackend("read-only", MASK64, 0x82000020, frozenset(), handler)]
        )
        with self.assertRaises(RehostError) as raised:
            router.dispatch(SmcCall.from_registers(0x4000, x0=0x82000020))
        self.assertEqual(raised.exception.code, "SMC_EFFECT_UNDECLARED")


if __name__ == "__main__":
    unittest.main()
