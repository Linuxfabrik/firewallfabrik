# Example: Virtual Data Center (`vdc.fwf`)

`vdc.fwf` is a FirewallFabrik project file describing the firewall configuration for a small virtual data center. Open it in FirewallFabrik (`fwf`) to inspect or modify the rulesets, then compile to generate deployable shell scripts.

## Topology

A single gateway (`firewall`) with a public interface (`eth0`, 198.51.100.200) and a private interface (`eth1`, 192.0.2.0/24) protects four internal VMs:

| VM | IP | Role |
|----|-----|------|
| `cloud` | 192.0.2.5 | Nextcloud + Collabora Online |
| `infra` | 192.0.2.2 | Infrastructure services |
| `monitor` | 192.0.2.4 | Monitoring (Icinga) |
| `proxy` | 192.0.2.3 | Reverse proxy |

All internal VMs are tagged `internal`. The project deliberately mixes platforms -- `cloud`, `proxy` and the gateway use nftables, while `infra` and `monitor` use iptables. The gateway handles NAT and forwarding between the public internet and the private network.

