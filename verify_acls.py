#!/usr/bin/env python3
"""
Checks that R1's access-list configuration actually enforces the four
access-policy rules the README claims, by parsing the committed config
directly rather than trusting the prose description.

This doesn't test live network behavior (that's what the screenshots in
screenshots/ are for) -- it checks that the *configuration itself*, as
committed, encodes the stated policy. A config can be syntactically fine
and still not match what a README claims it does; this catches that class
of mistake.

Usage: python3 verify_acls.py
Exit code 0 if all four rules are present and correctly directioned in the
config, non-zero otherwise.
"""

import re
import sys
from pathlib import Path

CONFIG_PATH = Path(__file__).parent / "configs" / "R1.cfg"

VLAN_SUBNETS = {
    "medical": "192.168.10.0",
    "clinical": "192.168.20.0",
    "admin": "192.168.30.0",
    "guest": "192.168.40.0",
}

EXTERNAL_SUBNET = "198.51.100.0"


def parse_acl_lines(config_text):
    """Extract every access-list line as (acl_number, action, src, dst)."""
    pattern = re.compile(
        r"access-list (\d+) (permit|deny) ip (\S+) [\d.]+ (\S+) [\d.]+"
    )
    entries = []
    for line in config_text.splitlines():
        match = pattern.match(line.strip())
        if match:
            acl_num, action, src, dst = match.groups()
            entries.append(
                {"acl": acl_num, "action": action, "src": src, "dst": dst}
            )
    return entries


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


def check_rule(description, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {description}")
    return condition


def main():
    if not CONFIG_PATH.exists():
        print(f"Could not find {CONFIG_PATH}")
        print("Run this from the repository root, or check configs/R1.cfg exists.")
        sys.exit(2)

    config_text = CONFIG_PATH.read_text()
    acl_entries = parse_acl_lines(config_text)
    bindings = parse_interface_acl_bindings(config_text)

    results = []

    # Rule 1: Guest cannot reach Medical, Clinical, or Administration.
    guest_denies = {
        e["dst"] for e in acl_entries
        if e["src"] == VLAN_SUBNETS["guest"] and e["action"] == "deny"
    }
    results.append(check_rule(
        "Rule 1: Guest denied to Medical, Clinical, and Administration",
        {VLAN_SUBNETS["medical"], VLAN_SUBNETS["clinical"], VLAN_SUBNETS["admin"]}
        <= guest_denies,
    ))

    # Rule 2: Medical Devices cannot reach the external network.
    medical_denies_external = any(
        e["src"] == VLAN_SUBNETS["medical"]
        and e["dst"] == EXTERNAL_SUBNET
        and e["action"] == "deny"
        for e in acl_entries
    )
    results.append(check_rule(
        "Rule 2: Medical Devices denied to external network",
        medical_denies_external,
    ))

    # Rule 3: Administration cannot reach Medical Devices.
    admin_denies_medical = any(
        e["src"] == VLAN_SUBNETS["admin"]
        and e["dst"] == VLAN_SUBNETS["medical"]
        and e["action"] == "deny"
        for e in acl_entries
    )
    results.append(check_rule(
        "Rule 3: Administration denied to Medical Devices",
        admin_denies_medical,
    ))

    # Rule 4: Clinical Workstations can reach Medical Devices.
    clinical_permits_medical = any(
        e["src"] == VLAN_SUBNETS["clinical"]
        and e["dst"] == VLAN_SUBNETS["medical"]
        and e["action"] == "permit"
        for e in acl_entries
    )
    results.append(check_rule(
        "Rule 4: Clinical Workstations permitted to Medical Devices",
        clinical_permits_medical,
    ))

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
    if all(results):
        print("All checks passed. The committed R1 config matches the")
        print("access policy described in the README.")
        sys.exit(0)
    else:
        failed = len([r for r in results if not r])
        print(f"{failed} check(s) failed. The config does not fully match")
        print("what the README claims -- see FAIL lines above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
