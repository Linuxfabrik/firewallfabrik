# Example: Virtual Data Center (`vdc.fwf`)

`vdc.fwf` is a FirewallFabrik project file describing the firewall configuration for a small virtual data center. It is meant as the starting point for a new one: copy it, rename the objects, adjust the addresses and services, and compile. Open it in FirewallFabrik (`fwf`) to inspect or modify the rulesets, then compile to generate deployable shell scripts.

The addresses are documentation addresses (RFC 5737). Replace them with the real ones.


## Topology

A single gateway (`firewall`) with a public interface (`eth0`, 198.51.100.200), a private interface (`eth1`, 192.0.2.1 in 192.0.2.0/24) and an OpenVPN interface (`tun0`, 203.0.113.1 in 203.0.113.0/24) protects five internal VMs:

| VM | IP | Role | Tags |
|----|-----|------|------|
| `cloud` | 192.0.2.5 | Nextcloud and Collabora Online | `internal` |
| `comm` | 192.0.2.6 | TURN server for Nextcloud Talk | `internal` |
| `infra` | 192.0.2.2 | DNS, NTP and FreeIPA | `internal`, `dns`, `ntp`, `freeipa` |
| `monitor` | 192.0.2.4 | Icinga and Grafana | `internal`, `monitoring` |
| `proxy` | 192.0.2.3 | Reverse proxy for every web service | `internal` |

The gateway is tagged `gateway`. All firewalls use nftables, and every one of them compiles a dual-stack policy.


## Building Blocks

**Roles instead of hosts.** Rules address the dynamic groups `dns vms`, `ntp vms`, `freeipa vms`, `monitoring vms` and `internal vms`, which select firewalls by tag. A second DNS or monitoring server only needs the tag, and every rule on the gateway and on the VMs follows.

**External services in groups.** `dns group` holds the DNS forwarders of the `dns vms`, `ntp group` their upstream NTP servers (DNS name objects, resolved at compile time). The `dns vms` and `ntp vms` may reach these and nothing else.

**The gateway (`firewall`)**:

- anti-spoofing on `eth0`: the gateway's own addresses, the internal and the OpenVPN network, RFC 1918 and link-local sources are logged and dropped
- NAT: HTTP and HTTPS to `proxy`, TURN to `comm`, Icinga from the office (198.51.100.74) to `monitor`, and SNAT for everything leaving through `eth0`
- OpenVPN clients reach every service on the internal network and the gateway, but not the Internet through the tunnel; that is rejected without logging
- SSH on port 2222 from the office directly on `eth0` as emergency access, and from there on to the VMs
- IPv4 forwarding is switched on; every other host leaves forwarding to the OS

**Every VM**:

- loopback accepted statelessly, one rule per address family (`::1` is on `lo`)
- SSH only from the OpenVPN network and from the gateway
- outbound HTTP/HTTPS for package updates, mail only through a relay on port 587 (`cloud` and `comm` also read mail over IMAPS)
- DNS, NTP and FreeIPA only to the `infra` roles, Icinga only to and from the `monitoring vms`
- a final rule that logs and drops all IPv6 the rules above do not accept

**Settings on every firewall**: packets in state INVALID are dropped and logged, logging is limited to 10 per second, interface addresses are never configured by the script, and the scripts are installed as user `linuxfabrik` with the activation command in the Installer tab. The prolog and epilog of `firewall` and `proxy` stop fail2ban before the ruleset is replaced and start it again afterwards; on `firewall` the prolog also waits for the OpenVPN interface.


## Starting a New VDC

1. Copy `vdc.fwf` and rename the firewalls and the objects that carry names or addresses (`internal network`, `openvpn network`, `office 198.51.100.74`).
2. Set the interface addresses of every firewall, its management interface and the alternative address the installer connects to.
3. Adjust the tags to the roles of the new hosts. The dynamic groups and the rules follow.
4. Fill `dns group` and `ntp group` with the servers the DNS and NTP hosts actually use.
5. Review the NAT rules, the application ports of each VM and the services in the user library (`ssh 2222`, `openvpn 1194`, `icinga 35665`).
6. Compile every firewall and read the warnings before the first installation.
