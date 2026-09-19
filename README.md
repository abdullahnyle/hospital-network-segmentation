# Hospital Network Segmentation

A Cisco Packet Tracer coursework project with four hospital network zones, router ACLs, exported configurations, and a Python policy checker.

## What this is for

Hospitals put a strange mix of devices on one network. Infusion pumps and ventilators sit next to nursing workstations, admin PCs handling billing and records, and guest wifi for visitors and patients. If all of that lives on one flat network, a compromised guest laptop is one hop away from a medical device, and a phishing email opened on an admin PC is one hop away from patient care equipment. Segmentation is the standard answer: split the network into zones by what a device is and what it's allowed to touch, then enforce that with routing and access control instead of hoping nobody plugs into the wrong port.

This project builds that segmentation for a small hospital network and documents the reasoning behind every zone and every rule, not just the configuration that implements them.

## Topology

Fifteen devices: two routers, two switches, nine end devices, two servers.

- **R1** - Cisco 2911, router-on-a-stick, handles inter-VLAN routing via subinterfaces and enforces the access policy
- **R-EXT** - Cisco 2911, represents the hospital's external-facing router
- **SW1, SW2** - Cisco 2960-24TT, access switches carrying the four VLANs
- Nine PCs across the four zones, plus Clinical-Server and External-Server

R1 connects to SW1 over an 802.1Q trunk and routes between VLANs using four subinterfaces. A separate point-to-point link connects R1 to R-EXT, which in turn connects to External-Server, simulating an external network the hospital's internal segments talk to under restricted conditions.

## The four zones

| VLAN | Zone | Subnet | Rationale |
|---|---|---|---|
| 10 | Medical Devices | 192.168.10.0/24 | Infusion pumps, ventilators, imaging consoles. The highest-consequence devices on the network and the ones with the least ability to defend themselves, most run fixed-purpose software that can't run endpoint security the way a workstation can. |
| 20 | Clinical Workstations | 192.168.20.0/24 | Nursing and clinical staff terminals, plus the clinical server. These need to reach medical devices as part of normal patient care. |
| 30 | Administration | 192.168.30.0/24 | Billing, records, scheduling. No clinical function, no reason to touch medical devices. |
| 40 | Guest | 192.168.40.0/24 | Visitor and patient wifi. Untrusted by default, outbound internet access only. |

## Access policy

1. **Guest cannot reach Medical Devices, Clinical Workstations, or Administration.** Outbound traffic is otherwise permitted.
2. **Medical Devices cannot reach the external network.**
3. **Administration cannot reach Medical Devices.**
4. **Clinical Workstations can route to Medical Devices.** Other routed destinations remain permitted because the stated policy does not restrict them. The clinical server is on the same VLAN, so access to it does not traverse this router ACL.

Routed traffic is filtered inbound on its source VLAN's R1 subinterface. ACLs are evaluated in order, with the first matching rule deciding the result and an implicit deny at the end. Outbound ACLs are also valid, but would require a different placement and policy design.

### Effective routed policy

| Source | Medical | Clinical | Administration | Guest | External subnet |
|---|---|---|---|---|---|
| Medical | Same VLAN | Permit | Permit | Permit | Deny |
| Clinical | Permit | Same VLAN | Permit | Permit | Permit |
| Administration | Deny | Permit | Same VLAN | Permit | Permit |
| Guest | Deny | Deny | Deny | Same VLAN | Permit |

This table describes individual packets at the source ACL, not complete bidirectional sessions. These ACLs are stateless: a Medical packet can reach Administration, but the Administration reply is denied. They do not provide general isolation between every pair of zones.

ACL 140 previously ended after the Clinical-to-Medical permit. Cisco's implicit deny therefore blocked every other routed Clinical flow, which did not match the four stated restrictions above. The final permit corrects the configuration to match the documented policy. It does not establish what the original historical intention was.

Run `python verify_acls.py` to check representative flows, rule order, implicit denial, exact inbound bindings, and switch VLAN assignments. Run `python -m unittest discover -s tests` for checker regression tests. The checker supports the numbered `ip` ACL syntax in these exports; it does not simulate routing, application sessions, DHCP, or the binary Packet Tracer file.

## Why four zones, and what that costs

Four zones is a choice, not the obvious answer. It would be simpler to run two zones, medical-and-clinical together and everything else separate, and simpler still to run one flat network with no segmentation at all. Both of those are worse for security and both of those are less work to administer. That trade runs in both directions and it's worth being honest about which way this design went.

The configured ACLs block Guest traffic to the internal zones, Medical traffic to the external segment, and Administration traffic to Medical. Other paths remain permitted, as shown in the table above. Segmentation reduces specific paths for lateral movement; it does not establish complete containment or validate a production hospital design.

It costs administrative burden, and that cost is real, not theoretical. Every device that gets added to the network needs to be classified into the correct zone before it's plugged in. Every time a device moves, physically or organizationally, someone has to update its VLAN assignment. A new infusion pump model, a nurse's workstation getting swapped out, a new admin hire's laptop: each of these is a small decision that has to be made correctly, every time, by whoever's doing hospital IT. The extra zones add classification and configuration work; this project does not measure that overhead. This design accepts that cost because the alternative, an infusion pump reachable from guest wifi, is worse.

The specific number four also isn't arbitrary within this design. It maps to four distinct trust levels that already exist in how a hospital operates: devices that keep people alive, staff who operate on those devices, staff who don't need to touch them, and people who aren't staff at all. Splitting further, by department or by floor, would add zones without adding a trust distinction that matters for this policy, which is exactly the kind of scope creep this project deliberately avoided.

## Proving a rule works by showing it fail

Most demonstrations of a network prove that things work. This project includes an explicit demonstration that something is correctly blocked, because that's the actual evidence that the access policy does what this document claims.

The screenshots directory includes a ping from a guest device to a medical device timing out with an explicit `destination host unreachable` response from R1, placed next to a ping from a clinical workstation to the same device succeeding. The result is consistent with the configured ACL. An unreachable response alone does not identify the cause; the configuration and permitted control test provide additional context.

## What could not be determined, and what a real deployment would require

This is the most important section in this document, more important than the topology or the configs. A simulated network makes some decisions look final that would actually be the first open questions in a real deployment.

**This design assumes a device inventory that does not exist.** Every VLAN assignment in this project starts from already knowing what a device is: this is an infusion pump, this is an admin PC, this is a guest laptop. In a real hospital that inventory doesn't exist by default, and building it is not a paperwork exercise, it's the actual first step of any segmentation project. A device that isn't known can't be classified, and a device that isn't classified can't be put in the right zone. In practice this means the real first phase of a project like this is walking the building, or pulling from procurement and asset management systems, and building a list of every device that touches the network before anything gets segmented. This project skips that step because the simulated environment defines the device list in advance. A real one won't.

**DHCP is documented but not demonstrated as functioning.** All four DHCP pools are configured correctly, structurally, with the right networks, default routers, and exclusions. During the final build session the DHCP process stopped issuing leases across every VLAN, not just one, for reasons that weren't isolated before the deadline. Two separate fixes were attempted, bouncing the affected interface and restarting the DHCP service entirely, and neither resolved it. Rather than continue chasing an intermittent simulator-level fault against a fixed deadline, every end device was assigned a static IP address instead, and the recorded connectivity tests used that static addressing. Rule three remained unconfirmed. The DHCP pools remain in the configuration as a correct reference, but this project does not claim DHCP was proven working end to end, because it wasn't.

**Rule three's live behavior is unconfirmed.** The ACL denying Administration access to Medical Devices was written and applied, and its binding to the correct router subinterface was independently confirmed. Testing it live turned up a fault that could not be resolved in the time available: pings between other zones on the same switching path worked correctly, and the trunk and switch ports involved were checked and confirmed healthy, but Administration's traffic did not behave as expected and the specific cause, most likely something at the subinterface level, was not isolated before the deadline. The configuration is believed correct based on it matching the pattern of the other three rules exactly, but this document does not claim it as tested, because it wasn't.

**The external subnet is a simulation, not a demonstrated internet perimeter.** The project applies source-VLAN rules on R1, but it does not implement or test a complete inbound firewall policy on R-EXT. Inbound perimeter filtering is outside the demonstrated scope.

**Physical port to device mapping was confirmed at the VLAN level, not the individual cable level**, apart from InfusionPump-01. This is a coursework project working from a topology diagram, not a hospital with a cable management system, and it's worth naming that gap rather than implying a precision that isn't there.

**This project does not address what happens when a device needs to move between zones**, when a personal device shows up on the network unannounced, or what monitoring would catch a device behaving outside its zone's expected pattern. Those are real operational questions for any hospital running this design, and none of them are answered here.

None of this is a defense of leaving these questions open. It's a statement of what this project actually demonstrates versus what a production deployment would still need to work out, because presenting a simulated network as a finished answer to any of these questions would be a worse failure than naming them plainly.

## Test evidence

The four files in `screenshots/` show the topology, guest isolation, Medical-to-External denial, and Clinical-to-Medical connectivity. Plain-text router and switch exports are in `configs/`. The ACL 140 correction is present in the text configuration and policy checker. The Packet Tracer file and screenshots preserve the original coursework state and have not been rerun or regenerated after that correction.

## Repository contents

- `hospital-segmentation.pkt` - the Packet Tracer file, open with Packet Tracer 8.x or later
- `configs/` - plain text running configuration for R1, R-EXT, SW1, and SW2
- `screenshots/` - topology, connectivity tests, and configuration evidence
- `README.md` - this document

## A naming note

The original design proposal described the internet-facing piece of this topology as an external router or cloud device. What's built here is a full Cisco 2911 acting in that role, referred to throughout as R-EXT. That's a direct and legitimate implementation of what the proposal describes, just built with a concrete device rather than left abstract.

## Scope

This project deliberately excludes QoS and traffic prioritization, gateway redundancy (HSRP/VRRP), a three-tier network hierarchy, wireless controller configuration, NAT beyond what's needed to simulate an external segment, and any VLANs beyond the four listed above. None of these would demonstrate anything this project is meant to show, and each adds configuration time and debugging risk without adding to the actual argument being made. The scope here is deliberately narrow so that what's included could be done well, rather than broad and done thinly.

## License

MIT. See `LICENSE`.
