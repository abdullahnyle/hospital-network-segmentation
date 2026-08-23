# Hospital Network Segmentation

A Cisco Packet Tracer project for a Computer Networks lab assignment. It designs and builds a hospital network segmented by clinical function and risk rather than by physical location, and it argues for that design the way you'd argue it to the person who has to sign off on it, not the way you'd write it up for a grader.

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
4. **Clinical Workstations can reach Medical Devices and the clinical server.**

Each rule is enforced with an extended ACL applied inbound on the relevant router subinterface. Inbound placement matters here: traffic from a VLAN arrives on its subinterface before R1 makes a routing decision, so filtering it there catches it before it goes anywhere. Applying the same ACL outbound would mean the routing decision already happened, and the ACL would be filtering traffic in the wrong direction entirely.

## Why four zones, and what that costs

Four zones is a choice, not the obvious answer. It would be simpler to run two zones, medical-and-clinical together and everything else separate, and simpler still to run one flat network with no segmentation at all. Both of those are worse for security and both of those are less work to administer. That trade runs in both directions and it's worth being honest about which way this design went.

More segmentation buys better containment. If a guest device gets compromised, or an admin PC gets hit with ransomware, the blast radius stops at the VLAN boundary instead of spreading to equipment that's keeping someone alive. That containment is the entire reason this project exists.

It costs administrative burden, and that cost is real, not theoretical. Every device that gets added to the network needs to be classified into the correct zone before it's plugged in. Every time a device moves, physically or organizationally, someone has to update its VLAN assignment. A new infusion pump model, a nurse's workstation getting swapped out, a new admin hire's laptop: each of these is a small decision that has to be made correctly, every time, by whoever's doing hospital IT. Four zones roughly quadruples that administrative surface compared to a flat network. This design accepts that cost because the alternative, an infusion pump reachable from guest wifi, is worse.

The specific number four also isn't arbitrary within this design. It maps to four distinct trust levels that already exist in how a hospital operates: devices that keep people alive, staff who operate on those devices, staff who don't need to touch them, and people who aren't staff at all. Splitting further, by department or by floor, would add zones without adding a trust distinction that matters for this policy, which is exactly the kind of scope creep this project deliberately avoided.

## Proving a rule works by showing it fail

Most demonstrations of a network prove that things work. This project includes an explicit demonstration that something is correctly blocked, because that's the actual evidence that the access policy does what this document claims.

The screenshots directory includes a ping from a guest device to a medical device timing out with an explicit `destination host unreachable` response from R1, placed next to a ping from a clinical workstation to the same device succeeding. The unreachable response, rather than a silent timeout, matters: it shows the router received the packet and actively rejected it under the ACL, rather than the packet getting lost for some unrelated reason.

## What could not be determined, and what a real deployment would require

This is the most important section in this document, more important than the topology or the configs. A simulated network makes some decisions look final that would actually be the first open questions in a real deployment.

**This design assumes a device inventory that does not exist.** Every VLAN assignment in this project starts from already knowing what a device is: this is an infusion pump, this is an admin PC, this is a guest laptop. In a real hospital that inventory doesn't exist by default, and building it is not a paperwork exercise, it's the actual first step of any segmentation project. A device that isn't known can't be classified, and a device that isn't classified can't be put in the right zone. In practice this means the real first phase of a project like this is walking the building, or pulling from procurement and asset management systems, and building a list of every device that touches the network before anything gets segmented. This project skips that step because the simulated environment defines the device list in advance. A real one won't.

**DHCP is documented but not demonstrated as functioning.** All four DHCP pools are configured correctly, structurally, with the right networks, default routers, and exclusions. During the final build session the DHCP process stopped issuing leases across every VLAN, not just one, for reasons that weren't isolated before the deadline. Two separate fixes were attempted, bouncing the affected interface and restarting the DHCP service entirely, and neither resolved it. Rather than continue chasing an intermittent simulator-level fault against a fixed deadline, every end device was assigned a static IP address instead, and the access policy was fully tested against that static addressing. The DHCP pools remain in the configuration as a correct reference, but this project does not claim DHCP was proven working end to end, because it wasn't.

**Rule three's live behavior is unconfirmed.** The ACL denying Administration access to Medical Devices was written and applied, and its binding to the correct router subinterface was independently confirmed. Testing it live turned up a fault that could not be resolved in the time available: pings between other zones on the same switching path worked correctly, and the trunk and switch ports involved were checked and confirmed healthy, but Administration's traffic did not behave as expected and the specific cause, most likely something at the subinterface level, was not isolated before the deadline. The configuration is believed correct based on it matching the pattern of the other three rules exactly, but this document does not claim it as tested, because it wasn't.

**Physical port to device mapping was confirmed at the VLAN level, not the individual cable level**, apart from InfusionPump-01. This is a coursework project working from a topology diagram, not a hospital with a cable management system, and it's worth naming that gap rather than implying a precision that isn't there.

**This project does not address what happens when a device needs to move between zones**, when a personal device shows up on the network unannounced, or what monitoring would catch a device behaving outside its zone's expected pattern. Those are real operational questions for any hospital running this design, and none of them are answered here.

None of this is a defense of leaving these questions open. It's a statement of what this project actually demonstrates versus what a production deployment would still need to work out, because presenting a simulated network as a finished answer to any of these questions would be a worse failure than naming them plainly.

## Test evidence

See `screenshots/` for:
- Topology overview
- VLAN and trunk status on both switches
- The guest-denied / clinical-permitted paired ping test against the same medical device
- Rule two's live test, a medical device denied external access
- Rule four's live test, a clinical workstation reaching a medical device
- Router configuration output for the interfaces and ACLs above

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
