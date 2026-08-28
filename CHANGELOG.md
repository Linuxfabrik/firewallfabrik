# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

### Fixed

* Compiler (iptables): "Clamp MSS to MTU" reaches the generated script again on a firewall pinned to an older iptables release.
* Compiler (iptables): a custom service that matches on the connection state in lower case is recognised.
* Compiler (iptables): a rate limit whose table name is longer than iptables can store is cut and reported, so two rules that share a table by accident are named.
* Compiler (iptables, nftables): a branch rule that leads back to where it started is reported as a loop.
* Compiler (iptables, nftables): a logging rule whose netlink group, NFLOG copy range or queue threshold is unusable falls back to the default instead of breaking the activation.
* Compiler (iptables, nftables): a NAT rule whose interface group turns out to be empty is reported instead of applying to every interface the firewall has.
* Compiler (iptables, nftables): a routing rule whose metric is not a number is reported instead of breaking the compile.
* Compiler (iptables, nftables): a rule assigned to several interfaces is compiled for each of them separately, so a dual-stack rule no longer disappears from one address family because the first interface has no address in it.
* Compiler (iptables, nftables): a rule branching into a rule set of another firewall or cluster compiles that rule set into the script instead of jumping into an empty chain ([#156](https://github.com/Linuxfabrik/firewallfabrik/issues/156)).
* Compiler (iptables, nftables): a rule left out because a group it names is empty is no longer also reported as shadowing the rule below it.
* Compiler (iptables, nftables): a rule whose interface group turns out to be empty is reported instead of being compiled as a rule about every interface the firewall has.
* Compiler (iptables, nftables): a rule whose source or destination is a host object reaches the chains it belongs in; on a bridging firewall outbound rules to a broadcast address were left out.
* Compiler (iptables, nftables): a rule whose time object names an hour or a weekday that does not exist is reported instead of breaking the compile.
* Compiler (iptables, nftables): a rule written for "any interface except these" is no longer reported as shadowing an unrelated rule.
* Compiler (iptables, nftables): an address table whose file name needs the firewall's data directory is reported when the firewall names none.
* Compiler (iptables, nftables): an address table, a DNS name or a dynamic interface whose name holds shell syntax is reported instead of running as a command on the firewall.
* Compiler (iptables, nftables): an ICMP service with an impossible type or code is reported instead of breaking the activation.
* Compiler (iptables, nftables): an IP service naming a protocol number that does not exist is reported instead of matching every protocol.
* Compiler (iptables, nftables): the "Netlink group" set on a logging rule is used, not only the firewall-wide one.
* Compiler (nftables): a packet mark written in octal keeps the mask it was given.
* Compiler (nftables): the generated script checks that its tools are there before it touches the firewall.
* Editor: a rule branching into a rule set of another firewall keeps pointing at it after the file is saved and reopened.
* Editor: opening the action parameters of a NAT rule no longer risks clearing the rule's other settings.
* Editor: the Branch action can be set on a rule again, and the rule set it jumps into is chosen by dragging it out of the object tree ([#90](https://github.com/Linuxfabrik/firewallfabrik/issues/90)).
* Editor: the Branch action of a NAT rule names the NAT rule set it asks for, not the policy one.


## [v2.0.0] - 2026-08-24

**Highlights:** Both compilers went through a full correctness pass against Firewall Builder. Rules that used to compile into something other than what the GUI shows are now either compiled correctly or reported at compile time, instead of silently matching every address, every service or nothing at all. Recompile and review your rulesets after updating, and read the breaking changes first.

### Breaking Changes

* A rule set other than the firewall's top rule set is compiled into a chain of its own and only runs when a Branch rule jumps to it. Merge it into the top rule set if it is meant to apply everywhere.
* A rule set that sets neither "IPv4" nor "IPv6" is compiled for IPv4 only. Set it to "IPv4 and IPv6" to keep its IPv6 rules.

### Added

* Compiler (iptables, nftables): the "Limit matching rate" options that count per source, destination or port ([#121](https://github.com/Linuxfabrik/firewallfabrik/issues/121)).
* Compiler (iptables, nftables): the "Limit number of simultaneous connections" rule option ([#120](https://github.com/Linuxfabrik/firewallfabrik/issues/120)).

### Changed

* FirewallFabrik installs on Python 3.11 and newer, so current distributions no longer need a custom Python build.
* The nftables firewall settings no longer show three options that only ever applied to iptables.

### Removed

* The `--xt` option of `fwf-ipt`.

### Fixed

* Compiler (iptables): "Clear all rules" clears them on current distributions.
* Compiler (iptables): a firewall activating through `iptables-restore` loads its ruleset and keeps its rule comments and log prefixes.
* Compiler (iptables): a firewall pinned to an older iptables release gets rules that release can load; a firewall pinning nothing is compiled for current iptables.
* Compiler (iptables): a firewall that keeps other tools' rules manages its NAT and packet-marking rules the same way as its filter rules.
* Compiler (iptables): a name carrying shell syntax, whether of a rule set, branch, interface, address table or log prefix, is refused at compile time instead of running as a command on the firewall.
* Compiler (iptables): the generated script waits at most five seconds for the iptables lock instead of blocking an unattended rollout forever.
* Compiler (iptables, nftables): "Add virtual addresses for NAT" and "Add rules to permit IPv6 Neighbor Discovery" generate their rules ([#143](https://github.com/Linuxfabrik/firewallfabrik/issues/143)).
* Compiler (iptables, nftables): "Always permit SSH access from the management workstation" installs that rule in the ruleset, not only in `block` and `stop`.
* Compiler (iptables, nftables): "MAC address matching" on a host takes effect, and a MAC match is reported or dropped where the packet no longer carries one.
* Compiler (iptables, nftables): a Branch rule jumps into the rule set it names, including packet-marking rule sets, NAT branches and branches imported from a `.fwb` file.
* Compiler (iptables, nftables): a compile the compiler refuses writes no script, says so and exits non-zero.
* Compiler (iptables, nftables): a dual-stack firewall keeps each single-stack rule in the address family it names.
* Compiler (iptables, nftables): a Reject rule sends the ICMP message its reject type names, and falls back to the default type where a TCP reset cannot apply.
* Compiler (iptables, nftables): a rule about the firewall's own addresses, its networks, broadcast and multicast traffic or its bridged paths lands in the chains that traffic really takes.
* Compiler (iptables, nftables): a rule limited to a calendar window keeps that window.
* Compiler (iptables, nftables): a rule naming a host or interface whose address comes from DHCP or PPP matches the address the machine has.
* Compiler (iptables, nftables): a rule the compiler cannot express is reported and left out instead of being installed without that condition.
* Compiler (iptables, nftables): a rule whose source, destination or service resolves to nothing is left out instead of matching every address or every protocol.
* Compiler (iptables, nftables): a rule written for "any interface except these" no longer produces rules on loopback, unprotected, bridge-port and cluster interfaces.
* Compiler (iptables, nftables): an address table whose file is empty or unreadable no longer matches every address, and the file is checked before the running ruleset is replaced.
* Compiler (iptables, nftables): an IPv6 rule written for a whole network no longer matches a single address, and a value that is no netmask is reported at compile time ([#154](https://github.com/Linuxfabrik/firewallfabrik/issues/154)).
* Compiler (iptables, nftables): log prefixes, log levels and the NFLOG "Copy range" and "Queue threshold" settings reach the generated ruleset, and an over-long prefix is reported instead of cut.
* Compiler (iptables, nftables): NAT rules translate what the editor shows, among them port-only translations, one-to-one network maps, load balancing over several backends, MASQUERADE and exclusions.
* Compiler (iptables, nftables): rate limits and connection limits are enforced at the rate the editor names, and values the packet filter cannot take are reported at compile time.
* Compiler (iptables, nftables): routing rules install the routes they name; several rules for one destination become one route with several next hops, and an unreachable gateway is reported.
* Compiler (iptables, nftables): rules that tag packets, assign a traffic class or match a tag do so, and a Tag Service survives saving and reopening the file ([#122](https://github.com/Linuxfabrik/firewallfabrik/issues/122)).
* Compiler (iptables, nftables): the check for rules hidden by an earlier rule reports each finding once and names its rule set ([#136](https://github.com/Linuxfabrik/firewallfabrik/issues/136)).
* Compiler (iptables, nftables): the kernel-hardening, connection-tracking and packet-forwarding settings take effect, and a setting the file does not carry takes the default the dialog shows.
* Compiler (nftables): a negated address, service, interface or time restriction matches the opposite of what it names.
* Compiler (nftables): a rule matching a DNS name, a dynamic interface or an address table read on the firewall is filled in at activation time instead of being left out.
* Compiler (nftables): a rule set or object whose name collides with an nftables keyword or a chain name is renamed and the rename reported.
* Compiler (nftables): a ruleset nftables refuses leaves the running rules in place instead of the host with none.
* Compiler (nftables): generated rules carry a counter, so `nft list ruleset` shows per-rule hit counts.
* Compiler (nftables): the generated activation script reports success when the ruleset loaded.
* Editor: a netmask or an address the compilers cannot read is refused where it is typed.
* GUI: deleting an object disables the rules whose last source, destination or service it was.
* GUI: File > Import Library works.
* GUI: the firewall settings offer the same "Default action on Reject" choices as the per-rule action editor.
* Import: an object imported from a Firewall Builder file keeps its tags.
* Installing `firewallfabrik[gui]` resolves its Qt dependency again.


## [v1.9.0] - 2026-07-12

### Added

* CLI: `fwf-upgrade` converts a Firewall Builder `.fwb` file and brings an older `.fwf` file to the current format without opening the GUI ([#132](https://github.com/Linuxfabrik/firewallfabrik/issues/132)).


## [v1.8.1] - 2026-07-01

### Fixed

* GUI: FirewallFabrik no longer crashes when the object tree is rebuilt while a search is open.


## [v1.8.0] - 2026-06-29

### Added

* Compiler (iptables, nftables): the "Accept ICMP redirects" and "Accept source-routed packets" hardening settings also apply to IPv6.
* Compiler (nftables): the kernel-hardening and conntrack tuning settings of the firewall's Host OS settings are applied by the generated script.

### Deprecated

* Host OS setting "TCP fack": the Linux kernel dropped FACK loss detection, so the setting has no effect on any supported release.

### Fixed

* Compiler (iptables): the conntrack tuning settings reach the kernel.
* Compiler (nftables): switching a firewall from iptables to nftables removes the leftover iptables rules on activation, which could shadow the new ones.
* Compiler (nftables): the backup SSH access rule of the "block" action is generated, which could lock an administrator out.
* GUI: the "Update Standard Library" preview lists the affected firewalls and rules.


## [v1.7.0] - 2026-06-18

### Added

* GUI: "Collapse", "Collapse All", "Expand" and "Expand All" in the object tree context menu.

### Fixed

* GUI: editing a standalone IPv4 or IPv6 address no longer shows a Netmask field. On an interface address, where it matters, it still appears.
* GUI: selecting a predefined Any object shows what Any matches in a rule instead of an editable form with meaningless values.


## [v1.6.0] - 2026-05-07

### Added

* Compiler (iptables): the "Use kernel timezone" setting is honoured on time-restricted rules.
* Compiler (iptables, nftables): the "Log IP options", "Log TCP options" and "Log TCP sequence numbers" settings are honoured on logging rules.

### Changed

* GUI: File > Open Recent tells entries apart by their differing path segments.

### Fixed

* GUI: the iptables and nftables firewall settings no longer mark options as unsupported that the compiler does honour, among them "Drop new TCP sessions without SYN", "Log all rules" and "Clamp MSS to MTU".
* GUI: the nftables firewall settings grey out the options the nftables compiler does not implement. They accepted clicks and had no effect.


## [v1.5.1] - 2026-05-07

### Fixed

* GUI: opening the Platform Settings dialog of an nftables firewall no longer crashes.


## [v1.5.0] - 2026-04-29

### Added

* GUI: renaming a firewall, host or interface that has child objects offers to rename the children along the standard naming scheme.
* GUI: the Install options dialog takes a password or passphrase, so a passphrase-protected SSH key or password authentication works from the dialog ([#72](https://github.com/Linuxfabrik/firewallfabrik/issues/72)).

### Changed

* Compiler (iptables, nftables): an address range that covers an exact CIDR block is compiled to the short CIDR form.
* GUI: Dynamic Groups combine their criteria with AND instead of OR, which closes a class of overly permissive rules. A per-group selector switches back to OR ([#82](https://github.com/Linuxfabrik/firewallfabrik/issues/82)).
* GUI: the interface context menu no longer offers "New Attached Networks" or "New Failover Group". Both return with the cluster support ([#78](https://github.com/Linuxfabrik/firewallfabrik/issues/78), [#84](https://github.com/Linuxfabrik/firewallfabrik/issues/84), [#85](https://github.com/Linuxfabrik/firewallfabrik/issues/85)).
* GUI: the Policy and NAT action menus no longer offer "Branch". It returns with full branch support ([#83](https://github.com/Linuxfabrik/firewallfabrik/issues/83), [#90](https://github.com/Linuxfabrik/firewallfabrik/issues/90)).

### Fixed

* CLI: `fwf-ipt --all` and `fwf-nft --all` skip firewalls flagged inactive ([#89](https://github.com/Linuxfabrik/firewallfabrik/issues/89)).
* Compiler (iptables): a firewall used as source or destination expands to one rule per own address, so an anti-spoofing rule covers the other own addresses too.
* Compiler (iptables): recompiling an unchanged policy produces a byte-identical script, so CI pipelines no longer see phantom changes.
* Compiler (iptables): the "TCP fin timeout" and "TCP keepalive interval" settings left at their default are no longer pushed into the kernel as 0.
* Compiler (iptables): with "Use iptables-restore" the rules are written in the form iptables-restore accepts, which it used to reject ([#77](https://github.com/Linuxfabrik/firewallfabrik/issues/77)).
* Compiler (iptables, nftables): a custom service that has code for the target platform is recognised instead of aborting the compile ([#71](https://github.com/Linuxfabrik/firewallfabrik/issues/71)).
* Compiler (iptables, nftables): a firewall interface with address 0.0.0.0 or :: or with netmask /0 aborts with a clear error instead of producing dead rules.
* Compiler (iptables, nftables): Custom, Tag and User Services reach the generated rules. Their code was dropped, so an established/related rule became a bare accept ([#72](https://github.com/Linuxfabrik/firewallfabrik/issues/72)).
* Compiler (iptables, nftables): IPv6 reject rules use the IPv6 reject types, so the IPv6 script loads on the firewall.
* Compiler (iptables, nftables): no more spurious shadowing warnings for rules whose source or destination is "any" and for TCP services that inspect TCP flags ([#73](https://github.com/Linuxfabrik/firewallfabrik/issues/73)).
* Compiler (iptables, nftables): rules that use an address range land in the right chains and are matched instead of being dropped, which produced permissive masquerading and missing rules.
* Compiler (nftables): a Reject rule with "TCP RST" on non-TCP services falls back to the configured reject action, and a rule mixing both is split.
* Compiler (nftables): an MSS clamping rule is generated when "Clamp MSS to path MTU" is set, matching iptables.
* Generated script: "stop" resets the built-in chain policies to ACCEPT after flushing. They stayed at DROP, so the firewall kept blocking all traffic after a stop.
* Generated script: every action checks for the tool it needs and aborts with a clear message.
* GUI: File > Reload works for native `.fwf` files and imported `.fwb` files alike.
* GUI: the Install rules destination path is no longer built by concatenating the local output path with the remote directory, which aborted the copy ([#72](https://github.com/Linuxfabrik/firewallfabrik/issues/72)).

### Removed

* The legacy "Use ULOG" firewall option. The Linux kernel removed the ULOG target years ago; a `.fwb` file that still carries it is migrated to LOG on import.
* The nftables firewall settings no longer expose iptables-only options the nftables compiler cannot act on.

### Security

* The Firewall Builder `.fwb` importer is hardened against malformed and malicious input files. Regular files import unchanged.


## [v1.4.6] - 2026-04-09

### Fixed

* GUI: all popup dialogs have a visible border on GNOME/Wayland.
* GUI: the Options column of the Policy, NAT and Routing editors shows the "Options" icon when non-default rule options are set.


## [v1.4.5] - 2026-04-09

### Changed

* GUI: the Compile dialog groups each firewall under its own heading and reports "Compiled with Warnings" or "Compile Error" in the progress column.

### Fixed

* Compiler (iptables): the generated scripts are POSIX sh compliant and pass shellcheck without warnings ([#36](https://github.com/Linuxfabrik/firewallfabrik/issues/36)).
* Compiler (iptables, nftables): a compiler warning no longer makes the compilation report as failed; the exit code stays 0.
* GUI: the Delete key works on selected elements in the policy editor.
* GUI: the scrollbars in the object tree and policy editor are visible on every desktop theme.


## [v1.4.4] - 2026-04-08

### Fixed

* GUI: no more sporadic crash when rebuilding the object tree after compilation or when closing and creating files ([#57](https://github.com/Linuxfabrik/firewallfabrik/issues/57)).
* GUI: the Custom Service editor remembers the selected platform instead of resetting to nftables ([#61](https://github.com/Linuxfabrik/firewallfabrik/issues/61)).


## [v1.4.2] - 2026-04-08

### Fixed

* GUI: the object tree attribute column is wide enough on first use when "Show object attributes in the tree" is enabled ([#60](https://github.com/Linuxfabrik/firewallfabrik/issues/60)).


## [v1.4.1] - 2026-04-08

### Fixed

* GUI: `pyside6-rcc` is found when FirewallFabrik is installed with `uv tool install` ([#58](https://github.com/Linuxfabrik/firewallfabrik/issues/58)).
* GUI: FirewallFabrik starts on Wayland-only systems such as GNOME without X11 ([#58](https://github.com/Linuxfabrik/firewallfabrik/issues/58)).
* GUI: no more sporadic crash when opening a rule editor while another editor has unsaved changes ([#57](https://github.com/Linuxfabrik/firewallfabrik/issues/57)).


## [v1.4.0] - 2026-03-29

### Added

* Compiler (iptables, nftables): "Flush entire ruleset". With the option off, FirewallFabrik only manages its own tables and chains and leaves rules created by Docker, CrowdSec or fail2ban untouched.

### Changed

* Defaults: output file name `fwf.sh` instead of the firewall object name, script directory `/etc` instead of `/etc/fw`, table and chain prefix `fwf` instead of `linuxfabrik`.

### Fixed

* Compiler (iptables, nftables): compiler messages name the rule position instead of the colour label.
* Compiler (iptables, nftables): IPv6 rules are generated from the rule set's address family setting instead of requiring IPv6 addresses on the firewall's interfaces ([#42](https://github.com/Linuxfabrik/firewallfabrik/issues/42)).
* Generated script: "stop" keeps the chain policies at DROP, so the host is not left wide open after a stop.
* Generated script: the script aborts on failure instead of continuing with an incomplete ruleset.
* Generated script: with "Flush entire ruleset" off, "status" detects whether the firewall is active even when other tools create additional chains.
* Generated script: with "Flush entire ruleset" off, "stop" removes all FirewallFabrik chains and jump rules, including sub-chains and the iptables-nft backend, and restores the chain policies to ACCEPT so other tools keep working ([#42](https://github.com/Linuxfabrik/firewallfabrik/issues/42)).
* GUI: FirewallFabrik no longer crashes when Ctrl+C is pressed in the terminal.
* GUI: IPv6 address and network dialogs accept prefix lengths 0 to 128 ([#50](https://github.com/Linuxfabrik/firewallfabrik/issues/50)).


## [v1.3.0] - 2026-03-17

### Added

* Compiler (iptables, nftables): bridge interfaces are configured through iproute2, and bridge ports are detected from the parent interface type.
* GUI: `Alt+Return` opens the editor for the selected object.
* GUI: Advanced Interface Settings dialog for device type (ethernet, VLAN, bridge, bonding), VLAN ID, STP and bonding parameters.
* GUI: Appearance tab in Preferences for fonts, direction and action text, comment clipping and toolbar labels.
* GUI: Installer tab in Preferences for SSH and SCP paths, timeout and password caching.
* GUI: Rules menu with insert, move, copy, cut, paste, remove, disable and enable.

### Changed

* Compiler (iptables, nftables): timestamps are gone from the generated scripts, so a deployment is idempotent.
* GUI: default label colours use the Solarized palette; "Purple" is now "Cluster" and "Gray" is now "Maintenance".
* GUI: FirewallFabrik runs natively on Wayland; the XCB fallback is gone.
* GUI: the "Unprotected interface" checkbox is gone from the interface editor, as it does not apply to iptables or nftables.

### Fixed

* Compiler (iptables, nftables): shadowing detection reports a warning instead of aborting the compilation, and no longer treats an address range as "any".


## [v1.2.0] - 2026-03-17

### Added

* Compiler (iptables, nftables): full Firewall Builder compiler parity, NFLOG as a logging target, and nftables load balancing and address set merging (closes #18, #22, #23, #24).
* GUI: a compile log error is clickable and scrolls to the firewall section it belongs to (closes #15).
* GUI: Cluster Member Management dialog to add and remove firewalls and view interface mappings (closes #26).
* GUI: Import Addresses from File, Library Import from `.fwf` or `.fwb`, and Library Export to a separate `.fwf` file (closes #12, #27).
* GUI: Inspect Rules shows all rules referencing the selected object (closes #28).
* GUI: Preferences dialog with DNS Name, Address Table, Policy Rules and Interface tabs, and Restore Defaults.
* Standard service library: Bareos, Keycloak, Kibana, Libvirt, Logstash, OpenSearch.

### Changed

* Compiler (iptables): the generated script runs `nft flush ruleset` on systems where `nft` is available.

### Fixed

* Compiler (iptables): the generated script carries the actual package version.
* Compiler (iptables, nftables): multiport rules were broken because the TCP flag check matched all TCP services (fixes #21).
* Compiler (iptables, nftables): no more false-positive shadowing errors.
* GUI: MAC address edits are saved instead of being silently ignored (fixes #14).
* GUI: opening an object for editing no longer marks the file as modified when nothing changed (fixes #25).


## [v1.1.0] - 2026-03-16

### Added

* Compiler (iptables): DSCP symbolic class names such as `AF11`, `EF` or `CS3`, and version-aware `ipv4options` formatting for releases before and after iptables 1.4.3.
* Compiler (iptables): fragment matching and IPv4 option matching in the filter compiler, which only the NAT compiler had.
* Compiler (iptables, nftables): the router-alert IP option.
* Compiler (nftables): DiffServ matching through `ip dscp` and `ip tos`.

### Changed

* GUI: the DiffServ default is DSCP instead of TOS.

### Fixed

* Compiler (iptables): TCP flag matching.
* Compiler (iptables, nftables): ICMP type and code matching in NAT rules.
* Compiler (iptables, nftables): no more shadowing false positives for IP services such as VRRP.


## [v1.0.1] - 2026-03-11

### Fixed

* The platform YAML defaults are part of the pip package again.


## [v1.0.0] - 2026-03-08

### Added

* CLI: `fwf-ipt` and `fwf-nft` accept several firewall names and `--all`.
* GUI: "Resolve Name" in the IPv4 and IPv6 address dialogs.
* GUI: a confirm-delete dialog for objects that are still in use.
* GUI: DynamicGroup editor with criteria table and matched-objects preview.
* GUI: File > Reload re-reads the current file from disk.
* GUI: NAT and Routing rule display, title bar dirty-state indicator, and a Window menu.
* GUI: parallel compilation of several firewalls, with ordered log output.
* GUI: subfolder paste, drag and drop, and nested object creation in the object tree.
* GUI: system theme icons (Breeze, Adwaita and others) for the toolbar and menus.
* MIME type definitions for `.fwf` and `.fwb` files.
* Standard service library: Collabora Online, FreeIPA, Icinga, Nextcloud notify_push, WinRM.

### Fixed

* Compiler (iptables, nftables): a firewall imported from a `.fwb` file compiles and installs without a prior save, and its Linux host settings reach the compiler.
* Compiler (iptables, nftables): rule shadowing detection is on by default, and its messages name the rule position.
* Compiler (nftables): `tcp flags != syn ct state new drop` is generated when "Accept new TCP with no SYN" is off.
* GUI: `.fwb` import detects the legacy Firewall Builder compiler paths and offers to clear them, so FirewallFabrik uses its built-in compiler.
* GUI: a new object created from the toolbar menu lands in the selected custom folder.
* GUI: dead menu entries are gone (File Compare, SNMP Discovery, Policy Import, Print, Help Contents and Index).
* GUI: deleting an object works regardless of how it is referenced.
* GUI: DynamicGroup, AddressTable and DNSName objects are allowed in rule source and destination cells.
* GUI: Find and Replace scope, tree filter and element display.
* GUI: the last active rule set is remembered by name, which survives an import.


## [v0.5.0rc1] - 2026-02-13

### Added

* GUI: an asterisk in the title bar when the file has unsaved changes.
* GUI: CIDR notation in the IPv4 and IPv6 editor dialogs.
* GUI: firewalls needing recompilation are shown in bold in the object tree.
* GUI: input validation in all editor dialogs.
* GUI: RuleSet editor dialog for Policy, NAT and Routing.

### Fixed

* GUI: Compile, Install and Save are disabled when no file is loaded.
* GUI: saving an imported `.fwb` warns before overwriting an existing `.fwf`.
* GUI: the Host OS and Platform Settings dialogs disable the options the compiler does not support.
* Installer: the remote paths and file names are correct.


## [v0.5.0b1] - 2026-02-13

Initial public beta pre-release.

### Added

* Compile and install workflow for iptables and nftables.
* GUI: detailed object tooltips in the rule editor.
* GUI: host wizard and group dialog ported from Firewall Builder.
* GUI: MDI rule set windows with multi-select drag, clipboard, delete and context menu.
* GUI: nftables settings dialog.
* GUI: object tree with library folder structure and nested group placement.
* GUI: single-rule compile for the target platform.
* Standard service library expanded with the Wikipedia multi-service ports.


[Unreleased]: https://github.com/Linuxfabrik/firewallfabrik/compare/v2.0.0...HEAD
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
