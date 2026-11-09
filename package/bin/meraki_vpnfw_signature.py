"""Turn a Meraki VPN firewall rule into the canonical signature that the
`meraki_vpnfw_signature(1)` macro computes from the syslog `pattern:` text.

The MX logs the compiled match expression of the rule, not its comment:

    rule  : allow tcp src=192.0.2.0/24 dst=198.51.100.10/32,198.51.100.11/32 dport=22
    syslog: allow tcp && (dst 198.51.100.10/32 || dst 198.51.100.11/32) && (dst port 22) && (src 192.0.2.0/24)
    rule  : allow Any/Any/Any/Any/Any (default rule)
    syslog: allow all

Clause order in the syslog line is not the field order of the rule, so the
signature sorts terms inside each clause and sorts the clauses themselves.
Both sides (this module and the SPL macro) must produce byte-identical
output: lowercase, parentheses stripped, plain ASCII sort.
"""

ANY = "any"
NO_MATCH_BODY = "all"


def _values(raw):
    """Split a comma-separated rule field; None when the field is 'Any'."""
    if raw is None:
        return None
    raw = str(raw).strip()
    if not raw or raw.lower() == ANY:
        return None
    return [v.strip().lower() for v in raw.split(",") if v.strip()]


def _clause(prefix, raw):
    values = _values(raw)
    if not values:
        return None
    return " || ".join(sorted(f"{prefix} {v}" for v in values))


def rule_signature(rule):
    """Canonical signature of one rule dict as returned by
    GET /organizations/{organizationId}/appliance/vpn/vpnFirewallRules."""
    clauses = []
    protocol = str(rule.get("protocol") or ANY).strip().lower()
    if protocol != ANY:
        clauses.append(protocol)
    for prefix, field in (
        ("src", "srcCidr"),
        ("src port", "srcPort"),
        ("dst", "destCidr"),
        ("dst port", "destPort"),
    ):
        clause = _clause(prefix, rule.get(field))
        if clause:
            clauses.append(clause)
    body = " && ".join(sorted(clauses)) if clauses else NO_MATCH_BODY
    return f"{str(rule.get('policy', '')).strip().lower()}|{body}"


def pattern_signature(pattern):
    """Python twin of the SPL macro, used by the tests to prove both sides agree."""
    pattern = pattern.strip()
    policy, _, body = pattern.partition(" ")
    policy = {"1": "allow", "0": "deny"}.get(policy, policy).lower()
    clauses = []
    for clause in body.split(" && "):
        clause = clause.strip().strip("()").strip().lower()
        clauses.append(" || ".join(sorted(t.strip() for t in clause.split(" || "))))
    return f"{policy}|{' && '.join(sorted(clauses))}"
