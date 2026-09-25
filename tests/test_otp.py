from __future__ import annotations

import unittest

from verirehost.errors import RehostError
from verirehost.otp import MonotonicOtp, OtpDecision, OtpRule
from verirehost.receipt import verify
from verirehost.smc_router import SideEffect


class MonotonicOtpTests(unittest.TestCase):
    def test_allow_rule_programs_once_and_is_monotonic(self) -> None:
        subject = MonotonicOtp(
            width=8,
            policy_id="synthetic-allow",
            rules=(
                OtpRule.from_context(
                    "authorized",
                    OtpDecision.ALLOW,
                    {"authorization": "present"},
                    allowed_set_mask=0x03,
                ),
            ),
            effect=SideEffect.FUSE,
        )
        first = subject.request_program(
            set_mask=0x01, context={"authorization": "present"}
        )
        second = subject.request_program(
            set_mask=0x01, context={"authorization": "present"}
        )
        self.assertEqual(first.changed_mask, 0x01)
        self.assertEqual(second.changed_mask, 0)
        self.assertEqual(subject.state, 0x01)
        verify(subject.receipt(model_id="synthetic-otp"))

    def test_deny_and_unknown_are_distinct(self) -> None:
        denied = MonotonicOtp(
            width=8,
            policy_id="synthetic-deny",
            rules=(),
            default_decision=OtpDecision.DENY,
        )
        unknown = MonotonicOtp(
            width=8,
            policy_id="synthetic-unknown",
            rules=(),
            default_decision=OtpDecision.UNKNOWN,
        )
        self.assertEqual(
            denied.request_program(set_mask=1, context={}).decision,
            OtpDecision.DENY,
        )
        self.assertEqual(
            unknown.request_program(set_mask=1, context={}).decision,
            OtpDecision.UNKNOWN,
        )
        self.assertEqual(denied.state, 0)
        self.assertEqual(unknown.state, 0)

    def test_clear_and_ambiguous_rules_fail_closed(self) -> None:
        subject = MonotonicOtp(
            width=8,
            policy_id="synthetic",
            rules=(
                OtpRule.from_context("one", OtpDecision.ALLOW),
                OtpRule.from_context("two", OtpDecision.DENY),
            ),
        )
        with self.assertRaises(RehostError) as ambiguous:
            subject.request_program(set_mask=1, context={})
        self.assertEqual(ambiguous.exception.code, "OTP_POLICY_AMBIGUOUS")
        with self.assertRaises(RehostError) as one_way:
            subject.request_program(set_mask=0, clear_mask=1, context={})
        self.assertEqual(one_way.exception.code, "OTP_ONE_WAY")


if __name__ == "__main__":
    unittest.main()
