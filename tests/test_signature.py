import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "package", "bin"))

from meraki_vpnfw_signature import pattern_signature, rule_signature  # noqa: E402

# Rule / syslog pairs in the exact format seen on MX 26.1 (documentation addresses).
OBSERVED = [
    (
        {"comment": "SSH", "policy": "allow", "protocol": "tcp", "srcPort": "Any",
         "srcCidr": "192.0.2.0/24", "destPort": "22",
         "destCidr": "198.51.100.10/32,198.51.100.11/32", "syslogEnabled": True},
        "allow tcp && (dst 198.51.100.10/32 || dst 198.51.100.11/32) && (dst port 22) && (src 192.0.2.0/24)",
    ),
    (
        {"comment": "TEST-2", "policy": "allow", "protocol": "tcp", "srcPort": "Any",
         "srcCidr": "Any", "destPort": "Any", "destCidr": "198.51.100.10/32", "syslogEnabled": True},
        "allow tcp && (dst 198.51.100.10/32)",
    ),
    (
        {"comment": "Default rule", "policy": "allow", "protocol": "Any", "srcPort": "Any",
         "srcCidr": "Any", "destPort": "Any", "destCidr": "Any", "syslogEnabled": True},
        "allow all",
    ),
]


class SignatureTest(unittest.TestCase):
    def test_observed_rules_match_their_syslog_pattern(self):
        for rule, pattern in OBSERVED:
            with self.subTest(rule=rule["comment"]):
                self.assertEqual(rule_signature(rule), pattern_signature(pattern))

    def test_rules_are_distinct(self):
        sigs = {rule_signature(r) for r, _ in OBSERVED}
        self.assertEqual(len(sigs), len(OBSERVED))

    def test_clause_order_is_ignored(self):
        self.assertEqual(
            pattern_signature("allow tcp && (src 192.0.2.0/24) && (dst port 22) && (dst 198.51.100.11/32 || dst 198.51.100.10/32)"),
            pattern_signature(OBSERVED[0][1]),
        )

    def test_numeric_policy_is_normalised(self):
        self.assertEqual(pattern_signature("1 all"), "allow|all")
        self.assertEqual(pattern_signature("0 icmp && (dst 203.0.113.13)"), "deny|dst 203.0.113.13 && icmp")

    def test_deny_and_allow_differ(self):
        rule = dict(OBSERVED[1][0], policy="deny")
        self.assertNotEqual(rule_signature(rule), rule_signature(OBSERVED[1][0]))


if __name__ == "__main__":
    unittest.main()
