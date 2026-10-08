# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

### Fixed

Compiler:

* a dynamic group also selects the interfaces, interface addresses and failover and state sync groups carrying its keyword
* a firewall with two routing rule sets holding rules is refused instead of installing the routes of one of them
* a NAT rule with a Tag Service as its translated service is reported and left out instead of translating without it
* a routing rule with a second gateway or interface, or with a network as its gateway, is reported and left out instead of losing the rest or stopping the activation
* a rule that still holds the "Dummy" placeholder is left out with a warning instead of matching any address, and an object called "Any" or "Dummy" is no longer dropped from rules

Data file:

* groups keep the order of their members through a save

Editor:

* deleting a cluster or an interface also deletes its failover and state sync groups and its sub-interfaces
* dragging in the tree only sorts objects into the subfolders of their own folder
* Find & Replace also replaces in groups, accepts dynamic and cluster groups, finds hosts and interfaces by address, and leaves a reference alone where the field does not take the replacement
* groups show their members in the tree, the tooltip and the group editor, interfaces included
* interfaces, MAC addresses, Attached Networks and dynamic groups can be put into an object group, and a group of interfaces into the interface field of a rule ([#189](https://github.com/Linuxfabrik/firewallfabrik/issues/189))
* pasting an interface brings its addresses and sub-interfaces, pasting into another file brings the objects the pasted object names, and rule sets and cluster groups can be copied
* pasting onto a group adds the object to the group instead of copying it into the group's folder, and pasting refuses what the target cannot hold
* rule fields only take objects that fit - one gateway and one interface in a route, no Tag Service as translated service, only interfaces of the firewall itself - and the drag cursor shows a refused drop
* the "Group" action leaves out objects the new group cannot hold
* the context menu offers its "New" entries by folder, so a user group named like a standard folder is a group; it offers no "New Routing Rule Set" and no new address on a dynamic, unnumbered or bridge-port interface, and the last rule set of a kind cannot be deleted
* "Where used" also lists branch targets, tagging services and cluster memberships, and changing one of them marks the firewalls using it for recompile


## [v3.3.0] - 2026-10-07

**Highlights:** Rate limits apply to a rule as a whole. A failed iptables activation keeps the previous ruleset, and an installation that locks you out rolls itself back after 60 seconds. File > Import Firewall takes over an existing iptables, nftables or firewalld setup.

### Added

Compiler:

* connection tracking helpers: a TCP or UDP service can name one, so FTP, TFTP, SIP and the like work again on kernels since 4.7; the standard FTP and TFTP services use theirs
* IPv6 reverse path filter, strict or loose
* rollback timer: an installation goes back to the previous ruleset unless the firewall answers a new SSH login within 60 seconds; the script offers the same as `try` and `confirm`
* two runs of the generated script, such as an installation and a timer, no longer change the firewall at the same time

Editor:

* File > Import Firewall takes over a running Linux firewall from its iptables, nftables or firewalld ruleset and its routes, from a file or over SSH; what cannot be carried over exactly blocks rather than lets through, and is marked ([#160](https://github.com/Linuxfabrik/firewallfabrik/issues/160))
* "Lookup Version ..." asks the firewall over SSH which iptables and nftables releases it runs
* the compile and install dialog and the object tree show each firewall's platform and release
* the reverse path filter offers loose mode, for firewalls with several uplinks or policy routing
* the rollback timeout can be set per firewall and, for new firewalls, in the preferences
* the version list names the distributions each entry is right for

Standard library:

* services for Amanda, gpsd, IRC over TLS, Jellyfin, Mumble, NSCA, NUT, Plex, SANE, Subversion, Syncthing, TeamSpeak and USB/IP ("Update Standard Library")

### Changed

Compiler:

* a firewall without a release set is compiled for the newest one, with a warning
* permitting IPv6 neighbour discovery also permits Multicast Listener Discovery, which switches with MLD snooping need

Editor:

* cluster members can no longer be marked as master, which had no effect on iptables or nftables
* the version list shows exact release ranges, newest first, and a new firewall starts with the newest

Standard library:

* ICMP type 11 code 1 is named "time exceeded in reassembly" ("Update Standard Library")

### Fixed

Compiler:

* a NAT rule that names an outgoing interface and translates nothing is no longer reported as an error
* a rule's rate limit applies to the rule as a whole and is no longer used up by traffic the rule does not match
* an outbound forwarding rule to a /32 or /128 network holding the firewall's own address is left out, as in Firewall Builder
* `reload_address_table` with `-6` reloads the IPv6 addresses of a run-time address table
* two branches into the same rule set no longer draw a loop warning
* iptables: a failed activation puts back the previous ruleset instead of leaving DROP policies and half the new rules; the script needs `iptables-save` and `ip6tables-save` for this
* iptables: a rate limit that applies only above the rate is compiled instead of left out
* iptables: on a kernel without the time match, such as RHEL 8 to 10, a script with time-of-day rules stops before it changes anything and says why
* iptables: warnings about the automatic mangle rules, such as MSS clamping, are shown
* nftables: a firewall set to the release it runs loads on Debian 11 and 12, openSUSE Leap 15.5, RHEL 8 and 9 and Ubuntu 22.04 and 24.04
* nftables: a logged rule with a rate limit logs only the packets the limit lets through
* nftables: a NAT branch into a rule set of the other address family is no longer an error
* nftables: per-source, per-destination and per-port rate limits load before nftables 1.1.0

CLI:

* `--xp` and `--xr` no longer run forever

Data file:

* a FirewallFabrik 1.x file compiles to its policy again instead of a script that drops everything

Editor:

* a new firewall or cluster starts with empty Policy, NAT and Routing rule sets, and a cluster with its state sync group
* clusters: the New Cluster wizard creates members that work and can take over the rules of one member, the install dialog lists the members under their cluster, and each member is installed with its own script ([#180](https://github.com/Linuxfabrik/firewallfabrik/issues/180))
* duplicating a firewall with sub-interfaces, a cluster or a rule branching into its own firewall works
* installing and "Lookup Version ..." use the IP address of the management interface when no alternative address is set ([#187](https://github.com/Linuxfabrik/firewallfabrik/pull/187))
* installing with a password no longer hangs, and a wrong password or an unknown host key is reported ([#181](https://github.com/Linuxfabrik/firewallfabrik/pull/181))

Standard library:

* the IPSEC group includes IKE (UDP 500) and NAT traversal (UDP 4500), so tunnels come up ("Update Standard Library")


## [v3.2.0] - 2026-09-25

**Highlights:** Several editor dialogs changed settings on a plain OK or showed them inverted, and now keep what is stored. If you ticked "Accept TCP sessions opened prior to firewall restart", check it again: it was saved inverted.

### Added

Editor:

* Time objects can have a start and an end date

### Fixed

Compiler:

* run-time address tables of a firewall imported from Firewall Builder find its Data directory

Editor:

* a Custom Service for IPv4 and IPv6 stays that way when edited
* a failover group without a known protocol falls back to VRRP
* "Accept TCP sessions opened prior to firewall restart" is no longer inverted, and untouched settings stay as they are on save ([#177](https://github.com/Linuxfabrik/firewallfabrik/issues/177), [#178](https://github.com/Linuxfabrik/firewallfabrik/issues/178))
* Rule Options keep the interface, hashlimit mode and "firewall is part of any" setting
* the interface settings no longer turn an "unknown" sub-interface of a bridge or bond into a port
* the Time editor shows the weekdays of intervals from older Firewall Builder files


## [v3.1.0] - 2026-09-22

**Highlights:** Invalid packets are dropped and logged by default. Block lists work at any size and can be updated at run time on nftables too. IPv6 routing works on dual-stack firewalls.

### Added

Compiler:

* nftables: Custom actions with TCPMSS, MARK, CONNMARK, CLASSIFY, NFQUEUE, NOTRACK or TRACE, and rules matching the ToS byte
* nftables: the script can reload, add to, remove from and test address tables at run time

Editor:

* a Custom action keeps one statement per packet filter, so switching a firewall between iptables and nftables no longer breaks it ([#161](https://github.com/Linuxfabrik/firewallfabrik/issues/161))

### Changed

Compiler:

* packets in state INVALID are dropped and logged as "INVALID state -- DENY" by default, and stateless rules no longer accept them
* the logging limit defaults to 10 messages per second; 0 logs without a limit

### Fixed

Compiler:

* a Branch rule still works after its target rule set was renamed
* a script compiled on Windows runs on Linux ([#175](https://github.com/Linuxfabrik/firewallfabrik/issues/175))
* an Address Table or DNS Name set to compile time is no longer resolved on the firewall
* IPv6 routing on dual-stack firewalls: link-local gateways, default routes per address family, multipath routes in the rollback, and repeated activations work
* NAT rules matching the ToS byte or a DiffServ code point are compiled, and a ToS value no packet can carry is reported
* iptables: "stop" no longer opens IPv6 or fails on a firewall without IPv6 rules
* iptables: a dual-stack firewall checks for `ip6tables` before installing rules, so a missing tool no longer leaves IPv6 open
* iptables: a firewall pinned below ip6tables 1.2.8 comes up with its rules
* iptables: a NAT rule translating to a DNS name resolved on the firewall is reported instead of aborting the activation at DROP
* iptables: run-time address tables load beyond 65536 addresses, handle IPv6 and report errors in their exit code
* nftables: a cluster NAT rule on an interface without a fixed address translates with the member's interface
* nftables: a failed address table reload keeps the loaded addresses, and tables beyond about 11,000 addresses or with comments load
* nftables: a firewall pinned to nftables 0.9.0 gets a ruleset that release loads
* nftables: a NAT rule excluding a list of addresses no longer adds them to a firewall interface
* nftables: a saved and reloaded dual-stack ruleset keeps IPv4 and IPv6 rules apart
* nftables: negated addresses and services match what the rule says, in policy and NAT rules
* nftables: Tag, Classify and connection-mark rules for the firewall's own traffic trigger policy routing, as on iptables

Data file:

* a `.fwf` file saved on Windows keeps Unix line endings
* rules of a hand-written `.fwf` file without positions are numbered in file order


## [v3.0.0] - 2026-09-04

**Highlights:** Clusters are supported, and the nftables compiler catches up with iptables. Many rules that silently matched something else, mostly around negation, now match what they say, and unusable configurations are refused. Recompile, review, and read the breaking changes first.

### Breaking Changes

* A bridge port named like a VLAN interface is refused unless the firewall also has an interface of its own under that name. Add it; nothing else creates the device.
* A firewall with an interface that has no address is refused instead of compiled. Give the interface an address, or take it out of the firewall object.
* A rule whose Custom action holds a command written for the other packet filter is reported and left out. Rewrite the statement after switching a firewall between iptables and nftables.
* The release a firewall names belongs to the platform it names, so a firewall switched between the two platforms may compile differently. Check the release in the firewall panel.

### Added

Compiler:

* "Attached Networks" objects in rules ([#85](https://github.com/Linuxfabrik/firewallfabrik/issues/85))
* clusters: compiling a cluster compiles each member with the cluster's interfaces, addresses, rule sets and routes, and permits the failover protocol and the state sync link ([#84](https://github.com/Linuxfabrik/firewallfabrik/issues/84))
* nftables: a rule the pinned release cannot parse is reported and left out instead of costing the whole ruleset
* nftables: Custom Services for connection state, TCP flags, socket owner and IPv6 routing header, Custom actions, negated time restrictions, translation to a DHCP or PPP address, and "Use SNAT instead of MASQUERADE"

Editor:

* a cluster editor, and failover and state sync groups with address, port and mode ([#78](https://github.com/Linuxfabrik/firewallfabrik/issues/78), [#84](https://github.com/Linuxfabrik/firewallfabrik/issues/84))
* "Attached Networks" objects on interfaces ([#85](https://github.com/Linuxfabrik/firewallfabrik/issues/85))
* the Branch action, with the target rule set dragged from the object tree ([#90](https://github.com/Linuxfabrik/firewallfabrik/issues/90))
* the firewall panel offers the iptables and nftables releases to compile for

Standard library:

* the "ESTABLISHED" custom services carry nftables code

### Fixed

Compiler:

* activation: a refused command fails the activation, "status" reports an active firewall, and "reload" no longer stops the firewall first
* branches into rule sets of other firewalls or clusters compile, and loops are reported ([#156](https://github.com/Linuxfabrik/firewallfabrik/issues/156))
* bridges, VLANs and bonds: bridges are built with all their ports and Docker, podman and libvirt bridges are left alone; interfaces the script cannot create are reported ([#95](https://github.com/Linuxfabrik/firewallfabrik/issues/95))
* clusters: groups with IPv6 addresses keep their rules, and DHCP cluster interfaces keep their NAT rules
* conntrack limits left unset no longer drop to zero, which made the kernel refuse every new connection
* routing: a failing route puts the previous table back and stops the activation unless marked non-critical, and an unreachable gateway is reported
* rules match what they name: empty groups and address tables, zero addresses, impossible service, time or metric values and over-long interface names are reported instead of matching everything or breaking the activation
* rules naming an interface cover all its addresses and VLANs, and rules on several interfaces are compiled for each
* iptables: ipsets are filled before the rules that use them, which lost every address-table rule on the first activation after a reboot
* iptables: keeping other tools' rules works with `iptables-restore`, without duplicating rules on every activation ([#42](https://github.com/Linuxfabrik/firewallfabrik/issues/42))
* iptables: rules with two negated elements match what they say; an "outside business hours" rule matched around the clock
* nftables: negated sources, destinations and services match what they say; several matched every packet
* nftables: the old rules are removed only after the new ones are in place, so an activation no longer leaves the machine unprotected
* nftables: the script finds `nft` and `ip` wherever the distribution puts them and checks its tools before touching the firewall

Editor:

* changing or deleting an object marks every firewall using it for recompile ([#159](https://github.com/Linuxfabrik/firewallfabrik/issues/159))
* failover and state sync groups are shown below their cluster objects and checked against them ([#78](https://github.com/Linuxfabrik/firewallfabrik/issues/78))
* renaming an interface or firewall renames its failover group and "Attached Networks" object
* the conntrack limits and TCP timeouts can be left at the kernel default
* the NAT action parameters no longer clear other rule settings


## [v2.0.0] - 2026-08-24

**Highlights:** Both compilers went through a full correctness pass against Firewall Builder. Rules that used to compile into something other than what the GUI shows are now either compiled correctly or reported at compile time, instead of silently matching every address, every service or nothing at all. Recompile and review your rulesets after updating, and read the breaking changes first.

### Breaking Changes

* A rule set other than the firewall's top rule set is compiled into a chain of its own and only runs when a Branch rule jumps to it. Merge it into the top rule set if it is meant to apply everywhere.
* A rule set that sets neither "IPv4" nor "IPv6" is compiled for IPv4 only. Set it to "IPv4 and IPv6" to keep its IPv6 rules.

### Added

Compiler:

* "Limit number of simultaneous connections" and the per-source, per-destination and per-port rate limits ([#120](https://github.com/Linuxfabrik/firewallfabrik/issues/120), [#121](https://github.com/Linuxfabrik/firewallfabrik/issues/121))

### Changed

* FirewallFabrik runs on Python 3.11 and newer.
* The nftables firewall settings no longer show three iptables-only options.

### Removed

* The `--xt` option of `fwf-ipt`.

### Fixed

Compiler:

* a compile the compiler refuses writes no script and exits non-zero
* a rule the compiler cannot express, or whose elements resolve to nothing, is reported and left out instead of matching every address, service or interface
* Branch rules, NAT rules, Reject types, tagging, classification, rate and connection limits, routing rules, calendar windows and log settings compile to what the editor shows ([#122](https://github.com/Linuxfabrik/firewallfabrik/issues/122))
* firewall options such as "Add virtual addresses for NAT", "Permit IPv6 Neighbor Discovery", "Always permit SSH access from the management workstation", kernel hardening and connection tracking take effect ([#143](https://github.com/Linuxfabrik/firewallfabrik/issues/143))
* IPv6 networks no longer match a single address, and invalid netmasks are reported ([#154](https://github.com/Linuxfabrik/firewallfabrik/issues/154))
* rules about the firewall's own addresses, networks, broadcast, multicast or bridged traffic land in the right chains, and dual-stack rules stay in their address family
* rules naming DHCP or PPP addresses match the machine's current address
* the shadowing check reports each finding once ([#136](https://github.com/Linuxfabrik/firewallfabrik/issues/136))
* iptables: "Clear all rules" works on current distributions, `iptables-restore` loads the ruleset, and an older pinned release gets rules it can load
* iptables: names carrying shell syntax are refused instead of running as commands on the firewall
* iptables: the script waits at most five seconds for the iptables lock
* nftables: a refused ruleset leaves the running rules in place, and success is reported only when the ruleset loaded
* nftables: DNS names, dynamic interfaces and run-time address tables are filled in at activation time
* nftables: names colliding with nftables keywords are renamed, with a warning
* nftables: rules carry counters

Editor:

* deleting an object disables the rules it was the last source, destination or service of
* File > Import Library works
* invalid netmasks and addresses are refused where they are typed
* the firewall settings offer the same reject types as the rule action editor

Import:

* objects imported from Firewall Builder keep their tags

Installation:

* `firewallfabrik[gui]` resolves its Qt dependency again


## [v1.9.0] - 2026-07-12

### Added

CLI:

* `fwf-upgrade` converts a Firewall Builder `.fwb` file or an older `.fwf` file without opening the GUI ([#132](https://github.com/Linuxfabrik/firewallfabrik/issues/132))


## [v1.8.1] - 2026-07-01

### Fixed

Editor:

* no crash when the object tree is rebuilt while a search is open


## [v1.8.0] - 2026-06-29

### Added

Compiler:

* the ICMP redirect and source routing hardening settings also apply to IPv6
* nftables: the kernel hardening and conntrack tuning settings of the Host OS are applied

### Deprecated

* Host OS setting "TCP fack": the kernel dropped FACK, so it has no effect.

### Fixed

Compiler:

* iptables: the conntrack tuning settings reach the kernel
* nftables: switching from iptables removes the leftover iptables rules on activation
* nftables: the "block" action keeps the backup SSH access rule

Editor:

* the "Update Standard Library" preview lists the affected firewalls and rules


## [v1.7.0] - 2026-06-18

### Added

Editor:

* "Collapse", "Collapse All", "Expand" and "Expand All" in the object tree

### Fixed

Editor:

* a standalone IPv4 or IPv6 address no longer shows a Netmask field
* the predefined Any object shows what it matches instead of an editable form


## [v1.6.0] - 2026-05-07

### Added

Compiler:

* "Log IP options", "Log TCP options" and "Log TCP sequence numbers"
* iptables: "Use kernel timezone" on time-restricted rules

### Changed

Editor:

* File > Open Recent tells entries apart by their path

### Fixed

Editor:

* the firewall settings mark the options correctly that each compiler supports


## [v1.5.1] - 2026-05-07

### Fixed

Editor:

* the Platform Settings dialog of an nftables firewall no longer crashes


## [v1.5.0] - 2026-04-29

### Added

Editor:

* renaming a firewall, host or interface offers to rename its child objects
* the Install dialog takes a password or key passphrase ([#72](https://github.com/Linuxfabrik/firewallfabrik/issues/72))

### Changed

Compiler:

* an address range that is an exact CIDR block is compiled as such

Editor:

* "Branch", "New Attached Networks" and "New Failover Group" are hidden until they are supported ([#78](https://github.com/Linuxfabrik/firewallfabrik/issues/78), [#83](https://github.com/Linuxfabrik/firewallfabrik/issues/83), [#84](https://github.com/Linuxfabrik/firewallfabrik/issues/84), [#85](https://github.com/Linuxfabrik/firewallfabrik/issues/85), [#90](https://github.com/Linuxfabrik/firewallfabrik/issues/90))
* Dynamic Groups combine their criteria with AND instead of OR, which closes a class of overly permissive rules; a per-group selector switches back ([#82](https://github.com/Linuxfabrik/firewallfabrik/issues/82))

### Fixed

Compiler:

* address ranges land in the right chains, which produced permissive masquerading and missing rules
* an interface with address 0.0.0.0, :: or netmask /0 is reported
* Custom, Tag and User Services reach the generated rules; an established/related rule used to become a bare accept ([#71](https://github.com/Linuxfabrik/firewallfabrik/issues/71), [#72](https://github.com/Linuxfabrik/firewallfabrik/issues/72))
* IPv6 reject rules use IPv6 reject types
* no more spurious shadowing warnings for "any" and TCP flag services ([#73](https://github.com/Linuxfabrik/firewallfabrik/issues/73))
* "stop" resets the chain policies to ACCEPT instead of leaving them at DROP
* the script checks for the tools it needs
* iptables: "Use iptables-restore" produces rules iptables-restore accepts ([#77](https://github.com/Linuxfabrik/firewallfabrik/issues/77))
* iptables: a firewall in source or destination covers all its own addresses
* iptables: an unchanged policy compiles to a byte-identical script
* iptables: TCP timeouts left at their default are no longer set to 0
* nftables: "Clamp MSS to path MTU" and Reject with TCP RST on non-TCP services work

CLI:

* `--all` skips inactive firewalls ([#89](https://github.com/Linuxfabrik/firewallfabrik/issues/89))

Editor:

* File > Reload works for `.fwf` and `.fwb` files
* installing copies to the right remote path ([#72](https://github.com/Linuxfabrik/firewallfabrik/issues/72))

### Removed

* iptables-only options in the nftables firewall settings.
* The "Use ULOG" option; a `.fwb` file carrying it is migrated to LOG.

### Security

* The `.fwb` importer is hardened against malformed and malicious files.


## [v1.4.6] - 2026-04-09

### Fixed

Editor:

* popup dialogs have a visible border on GNOME/Wayland
* the Options column shows its icon when non-default rule options are set


## [v1.4.5] - 2026-04-09

### Changed

Editor:

* the Compile dialog groups the output per firewall and shows warnings and errors in the progress column

### Fixed

Compiler:

* a warning no longer makes the compile report as failed
* iptables: the scripts are POSIX sh and pass shellcheck ([#36](https://github.com/Linuxfabrik/firewallfabrik/issues/36))

Editor:

* scrollbars are visible on every desktop theme
* the Delete key works in the policy editor


## [v1.4.4] - 2026-04-08

### Fixed

Editor:

* no sporadic crash when rebuilding the object tree or when closing and creating files ([#57](https://github.com/Linuxfabrik/firewallfabrik/issues/57))
* the Custom Service editor keeps the selected platform ([#61](https://github.com/Linuxfabrik/firewallfabrik/issues/61))


## [v1.4.2] - 2026-04-08

### Fixed

Editor:

* the attribute column of the object tree is wide enough on first use ([#60](https://github.com/Linuxfabrik/firewallfabrik/issues/60))


## [v1.4.1] - 2026-04-08

### Fixed

Editor:

* FirewallFabrik starts on Wayland-only systems and with `uv tool install` ([#58](https://github.com/Linuxfabrik/firewallfabrik/issues/58))
* no sporadic crash when opening a rule editor while another has unsaved changes ([#57](https://github.com/Linuxfabrik/firewallfabrik/issues/57))


## [v1.4.0] - 2026-03-29

### Added

Compiler:

* "Flush entire ruleset": switched off, FirewallFabrik manages only its own tables and chains and leaves those of Docker, CrowdSec or fail2ban alone

### Changed

* Defaults: script `fwf.sh` in `/etc`, table and chain prefix `fwf`.

### Fixed

Compiler:

* IPv6 rules follow the rule set's address family setting ([#42](https://github.com/Linuxfabrik/firewallfabrik/issues/42))
* messages name the rule position
* the script aborts on failure, "stop" no longer leaves the host open, and with "Flush entire ruleset" off "status" and "stop" handle other tools' chains ([#42](https://github.com/Linuxfabrik/firewallfabrik/issues/42))

Editor:

* IPv6 dialogs accept prefix lengths 0 to 128 ([#50](https://github.com/Linuxfabrik/firewallfabrik/issues/50))
* no crash on Ctrl+C in the terminal


## [v1.3.0] - 2026-03-17

### Added

Compiler:

* bridge interfaces are configured with iproute2

Editor:

* a Rules menu
* advanced interface settings for ethernet, VLAN, bridge and bonding
* `Alt+Return` opens the editor of the selected object
* Appearance and Installer tabs in the preferences

### Changed

Compiler:

* no timestamps in the generated scripts, so a deployment is idempotent

Editor:

* label colours use the Solarized palette; "Purple" is "Cluster" and "Gray" is "Maintenance"
* runs natively on Wayland
* the "Unprotected interface" checkbox is gone

### Fixed

Compiler:

* shadowing is a warning instead of an abort, and an address range is no longer treated as "any"


## [v1.2.0] - 2026-03-17

### Added

Compiler:

* Firewall Builder compiler parity, NFLOG, nftables load balancing and set merging ([#18](https://github.com/Linuxfabrik/firewallfabrik/issues/18), [#22](https://github.com/Linuxfabrik/firewallfabrik/issues/22), [#23](https://github.com/Linuxfabrik/firewallfabrik/issues/23), [#24](https://github.com/Linuxfabrik/firewallfabrik/issues/24))

Editor:

* a Preferences dialog
* clickable compile errors ([#15](https://github.com/Linuxfabrik/firewallfabrik/issues/15))
* Cluster Member Management ([#26](https://github.com/Linuxfabrik/firewallfabrik/issues/26))
* Import Addresses, Library Import and Export ([#12](https://github.com/Linuxfabrik/firewallfabrik/issues/12), [#27](https://github.com/Linuxfabrik/firewallfabrik/issues/27))
* Inspect Rules lists the rules using an object ([#28](https://github.com/Linuxfabrik/firewallfabrik/issues/28))

Standard library:

* Bareos, Keycloak, Kibana, Libvirt, Logstash, OpenSearch

### Changed

Compiler:

* iptables: the script runs `nft flush ruleset` where `nft` is available

### Fixed

Compiler:

* multiport rules work ([#21](https://github.com/Linuxfabrik/firewallfabrik/issues/21))
* no more false shadowing errors

Editor:

* MAC address edits are saved ([#14](https://github.com/Linuxfabrik/firewallfabrik/issues/14))
* opening an object no longer marks the file as modified ([#25](https://github.com/Linuxfabrik/firewallfabrik/issues/25))


## [v1.1.0] - 2026-03-16

### Added

Compiler:

* the router-alert IP option
* iptables: DSCP class names, fragment and IPv4 option matching in policy rules
* nftables: DiffServ matching

### Changed

Editor:

* DiffServ defaults to DSCP

### Fixed

Compiler:

* ICMP matching in NAT rules, and no shadowing false positives for IP services such as VRRP
* iptables: TCP flag matching


## [v1.0.1] - 2026-03-11

### Fixed

* The platform defaults are part of the pip package again.


## [v1.0.0] - 2026-03-08

### Added

CLI:

* `fwf-ipt` and `fwf-nft` take several firewall names and `--all`

Editor:

* Dynamic Group editor, NAT and Routing rule display, File > Reload, a Window menu
* MIME types for `.fwf` and `.fwb`
* parallel compilation of several firewalls
* "Resolve Name" in the address dialogs, and a warning before deleting objects in use

Standard library:

* Collabora Online, FreeIPA, Icinga, Nextcloud notify_push, WinRM

### Fixed

Compiler:

* a firewall imported from a `.fwb` file compiles and installs without a prior save
* shadowing detection is on by default
* nftables: "Accept new TCP with no SYN" off generates its drop rule

Editor:

* `.fwb` import offers to clear the legacy Firewall Builder compiler paths
* dead menu entries are gone
* deleting, Find and Replace and creating objects in custom folders work
* Dynamic Groups, Address Tables and DNS Names are allowed in rules


## [v0.5.0rc1] - 2026-02-13

### Added

Editor:

* firewalls needing a recompile are shown in bold
* Rule Set editor, CIDR notation, input validation, and an unsaved-changes marker

### Fixed

Editor:

* saving an imported `.fwb` warns before overwriting an existing `.fwf`
* the installer uses the right remote paths


## [v0.5.0b1] - 2026-02-13

Initial public beta pre-release: compile and install for iptables and nftables, with the Firewall Builder GUI.


[Unreleased]: https://github.com/Linuxfabrik/firewallfabrik/compare/v3.3.0...HEAD
[v3.3.0]: https://github.com/Linuxfabrik/firewallfabrik/compare/v3.2.0...v3.3.0
[v3.2.0]: https://github.com/Linuxfabrik/firewallfabrik/compare/v3.1.0...v3.2.0
[v3.1.0]: https://github.com/Linuxfabrik/firewallfabrik/compare/v3.0.0...v3.1.0
[v3.0.0]: https://github.com/Linuxfabrik/firewallfabrik/compare/v2.0.0...v3.0.0
[v2.0.0]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.9.0...v2.0.0
[v1.9.0]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.8.1...v1.9.0
[v1.8.1]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.8.0...v1.8.1
[v1.8.0]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.7.0...v1.8.0
[v1.7.0]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.6.0...v1.7.0
[v1.6.0]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.5.1...v1.6.0
[v1.5.1]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.5.0...v1.5.1
[v1.5.0]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.4.6...v1.5.0
[v1.4.6]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.4.5...v1.4.6
[v1.4.5]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.4.4...v1.4.5
[v1.4.4]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.4.3...v1.4.4
[v1.4.3]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.4.2...v1.4.3
[v1.4.2]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.4.1...v1.4.2
[v1.4.1]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.4.0...v1.4.1
[v1.4.0]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.3.0...v1.4.0
[v1.3.0]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.2.0...v1.3.0
[v1.2.0]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.1.0...v1.2.0
[v1.1.0]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.0.1...v1.1.0
[v1.0.1]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.0.0...v1.0.1
[v1.0.0]: https://github.com/Linuxfabrik/firewallfabrik/compare/v0.5.0rc1...v1.0.0
[v0.5.0rc1]: https://github.com/Linuxfabrik/firewallfabrik/compare/v0.5.0b1...v0.5.0rc1
[v0.5.0b1]: https://github.com/Linuxfabrik/firewallfabrik/releases/tag/v0.5.0b1
