#!/usr/bin/env python3
"""
Checks that the committed router and switch configs actually encode what
the README claims, rather than trusting the prose description on its own.

Two things get checked:
- R1's access-lists enforce the four access-policy rules from the README
  (guest denied to medical/clinical/admin, medical denied to external,
  admin denied to medical, clinical permitted to medical and otherwise).
- SW1 and SW2 define the same four VLANs with matching names, and their
  access ports land in the VLANs the README's zone table says they should.

This doesn't test live network behavior (that's what the screenshots in
screenshots/ are for) -- it checks that the configuration itself, as
committed, matches the stated design. A config can be syntactically fine
and still not match what a README claims it does; this catches that class
of mistake.

Usage: python3 verify_acls.py
Exit code 0 if every check passes, non-zero otherwise.
"""

from ipaddress import IPv4Address
import re
import sys
from pathlib import Path

CONFIG_DIR = Path(__file__).parent / "configs"
CONFIG_PATH = CONFIG_DIR / "R1.cfg"
SW1_PATH = CONFIG_DIR / "SW1.cfg"
SW2_PATH = CONFIG_DIR / "SW2.cfg"

VLAN_NAMES = {
    "10": "MEDICAL",
    "20": "CLINICAL",
    "30": "ADMIN",
    "40": "GUEST",
}

VLAN_SUBNETS = {
    "medical": "192.168.10.0",
    "clinical": "192.168.20.0",
    "admin": "192.168.30.0",
    "guest": "192.168.40.0",
}

EXTERNAL_SUBNET = "198.51.100.0"


def parse_acl_lines(config_text):
    """Extract every access-list line as (acl_number, action, src, dst)."""
    entries = []
    for line in config_text.splitlines():
        tokens = line.strip().split()
        if not tokens or tokens[0] != "access-list":
            continue
        if len(tokens) < 4 or tokens[2] not in {"permit", "deny"} or tokens[3] != "ip":
            raise ValueError(f"Unsupported ACL syntax: {line}")
        def address(offset):
            if tokens[offset] == "any":
                return (0, 0xffffffff), offset + 1
            if tokens[offset] == "host":
                return (int(IPv4Address(tokens[offset + 1])), 0), offset + 2
            return (int(IPv4Address(tokens[offset])), int(IPv4Address(tokens[offset + 1]))), offset + 2
        try:
            src, offset = address(4)
            dst, offset = address(offset)
        except (IndexError, ValueError) as exc:
            raise ValueError(f"Invalid ACL address: {line}") from exc
        if offset != len(tokens):
            raise ValueError(f"Unsupported ACL options: {line}")
        entries.append({"acl": tokens[1], "action": tokens[2], "src": src, "dst": dst})
    return entries


def evaluate_acl(entries, acl, source, destination):
    """Evaluate numbered IP rules in order, including the implicit deny."""
    def matches(value, rule):
        network, wildcard = rule
        mask = 0xffffffff ^ wildcard
        return (int(IPv4Address(value)) & mask) == (network & mask)
    for entry in entries:
        if entry["acl"] == acl and matches(source, entry["src"]) and matches(destination, entry["dst"]):
            return entry["action"]
    return "deny"


def parse_interface_acl_bindings(config_text):
    """Map each subinterface to the ACL number applied inbound on it."""
    bindings = {}
    current_iface = None
    for line in config_text.splitlines():
        line = line.strip()
        iface_match = re.match(r"interface (\S+)", line)
        if iface_match:
            current_iface = iface_match.group(1)
            continue
        acl_match = re.match(r"ip access-group (\d+) in", line)
        if acl_match and current_iface:
            bindings[current_iface] = acl_match.group(1)
    return bindings


def parse_vlan_names(config_text):
    """Extract each VLAN's number and name, in the order they're defined."""
    vlans = {}
    current_vlan = None
    for line in config_text.splitlines():
        line = line.strip()
        vlan_match = re.match(r"vlan (\d+)$", line)
        if vlan_match:
            current_vlan = vlan_match.group(1)
            continue
        name_match = re.match(r"name (\S+)", line)
        if name_match and current_vlan:
            vlans[current_vlan] = name_match.group(1)
            current_vlan = None
    return vlans


def parse_access_port_vlans(config_text):
    """Map each access-mode interface to the VLAN it's assigned."""
    ports = {}
    current_iface = None
    is_access = False
    for line in config_text.splitlines():
        line = line.strip()
        iface_match = re.match(r"interface (\S+)", line)
        if iface_match:
            current_iface = iface_match.group(1)
            is_access = False
            continue
        if line == "switchport mode access":
            is_access = True
            continue
        vlan_match = re.match(r"switchport access vlan (\d+)", line)
        if vlan_match and current_iface and is_access:
            ports[current_iface] = vlan_match.group(1)
    return ports


def check_rule(description, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {description}")
    return condition


def check_switch(name, path, expect_ports=None):
    """Verify a switch's VLAN names match the README's zone table, and
    optionally that specific access ports land in the expected VLAN."""
    if not path.exists():
        print(f"Could not find {path}")
        sys.exit(2)

    config_text = path.read_text()
    vlans = parse_vlan_names(config_text)
    ports = parse_access_port_vlans(config_text)

    results = []
    results.append(check_rule(
        f"{name}: all four VLANs (10/20/30/40) are defined",
        set(VLAN_NAMES) <= set(vlans),
    ))
    results.append(check_rule(
        f"{name}: VLAN names match the README's zone table",
        all(vlans.get(num) == label for num, label in VLAN_NAMES.items() if num in vlans),
    ))

    if expect_ports:
        for iface, expected_vlan in expect_ports.items():
            results.append(check_rule(
                f"{name}: {iface} is assigned to VLAN {expected_vlan} ({VLAN_NAMES[expected_vlan]})",
                ports.get(iface) == expected_vlan,
            ))

    return results


def main():
    if not CONFIG_PATH.exists():
        print(f"Could not find {CONFIG_PATH}")
        print("Run this from the repository root, or check configs/R1.cfg exists.")
        sys.exit(2)

    config_text = CONFIG_PATH.read_text()
    acl_entries = parse_acl_lines(config_text)
    bindings = parse_interface_acl_bindings(config_text)

    results = []

    expected_bindings = {"10": "120", "20": "140", "30": "130", "40": "110"}
    destinations = {"10": "192.168.10.25", "20": "192.168.20.25",
                    "30": "192.168.30.25", "40": "192.168.40.25",
                    "external": "198.51.100.25"}
    denied = {"10": {"external"}, "20": set(),
              "30": {"10"}, "40": {"10", "20", "30"}}
    for vlan, expected_acl in expected_bindings.items():
        iface = f"GigabitEthernet0/0.{vlan}"
        acl = bindings.get(iface)
        results.append(check_rule(f"{iface}: inbound ACL {expected_acl}", acl == expected_acl))
        for target, destination in destinations.items():
            if target == vlan:
                continue  # Same-VLAN traffic does not pass through R1.
            expected = "deny" if target in denied[vlan] else "permit"
            actual = evaluate_acl(acl_entries, acl, destinations[vlan], destination) if acl else "permit"
            results.append(check_rule(f"VLAN {vlan} -> {target}: {expected}", actual == expected))

    # Structural check: every ACL referenced by an interface binding
    # actually has at least one entry defined, and vice versa where
    # expected. This catches the class of mistake where an ACL is written
    # but never actually applied to an interface, or applied to the wrong
    # one -- a real risk in router-on-a-stick configs with several
    # subinterfaces.
    defined_acls = {e["acl"] for e in acl_entries}
    bound_acls = set(bindings.values())
    results.append(check_rule(
        "Every defined ACL is bound to an interface",
        defined_acls <= bound_acls,
    ))
    results.append(check_rule(
        "Every ACL bound to an interface has entries defined",
        bound_acls <= defined_acls,
    ))

    print()
    print("Checking switch VLAN assignments against the README's zone table...")
    print()

    sw1_results = check_switch(
        "SW1", SW1_PATH,
        expect_ports={
            "FastEthernet0/3": "10",
            "FastEthernet0/4": "10",
            "FastEthernet0/5": "20",
            "FastEthernet0/6": "20",
        },
    )
    print()
    sw2_results = check_switch(
        "SW2", SW2_PATH,
        expect_ports={
            "FastEthernet0/1": "10",
            "FastEthernet0/2": "20",
            "FastEthernet0/3": "30",
            "FastEthernet0/4": "30",
            "FastEthernet0/5": "40",
            "FastEthernet0/6": "40",
        },
    )

    results.extend(sw1_results)
    results.extend(sw2_results)

    print()
    if all(results):
        print("All checks passed for the sampled IP flows and configured access")
        print("policy and zone assignments described in the README.")
        sys.exit(0)
    else:
        failed = len([r for r in results if not r])
        print(f"{failed} check(s) failed. The configs do not fully match")
        print("what the README claims -- see FAIL lines above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
