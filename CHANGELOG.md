# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

### Changed

* CI: the lint, format, security and dead-code hooks run on every push and pull request, so the coding standards hold for contributors who have not installed the pre-commit hooks locally.
* CI: the test suite runs on every push and pull request, on every Python version the package claims to support. Until now nothing in CI executed a single test.
* CI: the documentation toolchain lockfile is watched by Dependabot, so it receives updates like every other lockfile in the repository.
* FirewallFabrik installs on Python 3.11 and newer, so current distributions no longer need a custom Python build for it.
* The nftables firewall settings no longer show three options that only ever applied to iptables. A firewall switched back to iptables keeps its values.

### Fixed

* Compiler (iptables): "Clear all rules" really clears them on current distributions. The firewall kept its old rules and grew with every activation, with all traffic blocked in the meantime.
* Compiler (iptables): a log prefix longer than the LOG or NFLOG target can carry is reported instead of being cut silently. nftables has room for the whole string, so the same policy wrote differently shaped log lines on the two platforms.
* Compiler (iptables): a rate limit higher than iptables can express is reported at compile time instead of stopping the activation script. nftables is unaffected.
* Compiler (iptables): a rule set or branch whose name iptables cannot use as a chain name is reported at compile time instead of failing during activation. nftables is unaffected.
* Compiler (iptables): bridging firewalls whose rules use an interface as a destination compile again instead of failing with an internal error and no script at all.
* Compiler (iptables): firewalls pinned to iptables 1.2.5 or to 1.2.6 through 1.2.8 are compiled for that release again.
* Compiler (iptables): firewalls that do not pin an iptables version are compiled for current iptables. Rules with a negated address or interface failed to load.
* Compiler (iptables): firewalls with routing rules generate a working script. One packet filter rule and the first route were lost.
* Compiler (iptables): IPv6 NAT rules that match a specific ICMPv6 type produce a valid rule.
* Compiler (iptables): log prefixes are written correctly on firewalls that activate through iptables-restore. Log messages ran into the packet data and broke log parsers.
* Compiler (iptables): masquerading rules that also translate the source port keep the configured port range instead of letting the kernel pick a port.
* Compiler (iptables): NAT rules whose translated address cannot be determined are reported and left out instead of stopping the activation script half way.
* Compiler (iptables): rules combining a TCP flag or IP option match with a rate limit or a time restriction load again. They were missing from the running firewall.
* Compiler (iptables): rules that assign a traffic class do so. Traffic shaping never saw the class.
* Compiler (iptables): rules that set a mark, a traffic class or a route and list several addresses or services set it only for those. The mark was set on every packet the rule's other conditions matched, and the listed addresses and services were never checked at all.
* Compiler (iptables): rules that name an interface and apply in both directions no longer stop the activation script.
* Compiler (iptables): rules that reject with a TCP reset also work when they are logged or negate their source, destination or service. The traffic fell through to the rule below instead.
* Compiler (iptables): rules that use a custom service load again instead of being rejected for a missing protocol match.
* Compiler (iptables): the `--xp` rule trace works on firewalls imported from a `.fwb` file instead of aborting the whole compile with an internal error.
* Compiler (iptables): the automatic MSS clamping and connection mark rules survive activation on firewalls that activate through iptables-restore. They were wiped again right after being set.
* Compiler (iptables): the generated script no longer creates and fills chains nothing ever jumps to. Dual-stack firewalls carried a copy of every IPv6-only rule in their IPv4 chains and vice versa.
* Compiler (iptables): the generated script waits at most five seconds for the iptables lock instead of blocking forever, which stalled unattended rollouts without an error.
* Compiler (iptables): the NFLOG "Copy range" setting takes effect, so the logging daemon receives only as much of each packet as the firewall asks for instead of always the whole one. Firewalls pinned to an iptables older than 1.6.1, which cannot express this, get a warning.
* Compiler (iptables): time-restricted rules load on firewalls pinned to an older iptables release.
* Compiler (iptables, nftables): "Add rules to permit IPv6 Neighbor Discovery" generates those rules. Dual-stack firewalls that drop by default lost IPv6 connectivity.
* Compiler (iptables, nftables): a bridge port is recognised as one, so the generated script no longer tries to configure an address on it and rules that name one are compiled again.
* Compiler (iptables, nftables): a dual-stack interface or host is matched by its IPv4 address in the IPv4 ruleset and by its IPv6 address in the IPv6 one, instead of always the first. A single-stack object is left out of the other family instead of producing a ruleset that does not load.
* Compiler (iptables, nftables): a NAT rule whose translated service uses a different protocol than the original is reported instead of being compiled into a translation the rule does not ask for.
* Compiler (iptables, nftables): a source translation to an unnumbered interface is reported instead of stopping the activation script on iptables and translating to the wrong address on nftables.
* Compiler (iptables, nftables): address ranges are no longer emitted into the wrong address family, which produced a ruleset that did not load.
* Compiler (iptables, nftables): an IP service with an unknown DiffServ class name is reported with a clear error instead of producing a ruleset that does not load.
* Compiler (iptables, nftables): dual-stack firewalls whose rules mix IPv4 and IPv6 addresses compile again.
* Compiler (iptables, nftables): IPv6 NAT rules that also translate the port produce a ruleset that loads.
* Compiler (iptables, nftables): NAT rules that name an interface which cannot apply to them are reported and left out. They stopped the activation script on iptables and translated nothing on nftables.
* Compiler (iptables, nftables): redirect rules that only match the connection owner, as a transparent proxy does, load again.
* Compiler (iptables, nftables): rules and NAT rules that match a MAC address produce a rule that loads.
* Compiler (iptables, nftables): rules that match a Tag Service match only the tagged packets instead of every packet, which let traffic through a rule meant to be selective.
* Compiler (iptables, nftables): rules that match a TCP service with all six flags inspected and only SYN required match a connection request, as Firewall Builder does. They also required FIN, PSH and URG to be clear, so a SYN packet carrying one of those slipped past.
* Compiler (iptables, nftables): rules that match a bridge port match the bridged traffic. On iptables the rule now looks at the bridge layer, and on nftables, which cannot do that in a filter table, the rule is reported and left out. Before, both platforms produced a rule that never matched, so an "accept" rule dropped the traffic and a "deny" rule let it through.
* Compiler (iptables, nftables): rules that match an interface which can never apply to them are reported and left out. They stopped the activation script on iptables and matched nothing on nftables.
* Compiler (iptables, nftables): rules that compile to the same command as an earlier rule are all kept. Whichever came second was silently dropped, so a firewall could be missing rules it shows in the GUI.
* Compiler (iptables, nftables): rules that reject with a TCP reset and use a custom TCP service keep that reject type instead of being downgraded with a spurious warning.
* Compiler (iptables, nftables): rules that tag packets set the tag. On iptables the activation script also stopped at such a rule.
* Compiler (iptables, nftables): NAT rules whose service cannot be expressed are left out instead of translating every protocol and port between the addresses they name. A transparent-proxy redirect meant for one user redirected everyone's traffic.
* Compiler (iptables, nftables): rules whose service cannot be expressed are left out instead of applying to every protocol and port. A rule for one service acted on all traffic, so a "reject this service" rule rejected everything from its source.
* Compiler (iptables, nftables): rules whose source or destination cannot be resolved are left out instead of applying to every address, where an "accept from these hosts" rule accepted from everywhere.
* Compiler (iptables, nftables): rules with a custom action run it instead of doing nothing. nftables cannot run one and reports the rule.
* Compiler (iptables, nftables): the firewall-wide limit on log messages reaches the generated ruleset. A logging firewall under load could fill its disk.
* Compiler (nftables): a firewall with weekday-restricted rules is warned when its time zone setting makes iptables and nftables pick different days. The warning was the wrong way round and fired exactly when the two agreed.
* Compiler (nftables): a firewall whose only rules are the automatic ones installs them together with its default-drop policy, instead of an empty ruleset that left the host open.
* Compiler (nftables): a NAT rule for an ICMP service translates only the message types it names instead of every ICMP packet between the addresses in the rule.
* Compiler (nftables): a NAT rule that excludes a group of addresses excludes all of them instead of still translating every one.
* Compiler (nftables): a NAT rule that translates the source and the destination is labelled in both chains of the generated ruleset, so its second half is no longer filed under an unrelated rule number.
* Compiler (nftables): a rule that lists several ICMP, IP or custom services covers all of them instead of only the first.
* Compiler (nftables): a rule that uses a loopback interface without an IP address reports a clear error instead of disappearing silently.
* Compiler (nftables): an IP service that matches fragmented packets does so instead of letting fragments through.
* Compiler (nftables): a rule that negates an IP service the compiler cannot invert is left out instead of being written the other way round, where it acted on exactly the traffic it was meant to spare.
* Compiler (nftables): an IP service that matches IP options carries that condition instead of matching every packet. The timestamp option, which nftables cannot match, is reported.
* Compiler (nftables): an IP service with protocol "any" no longer restricts the rule to a protocol that matches nothing.
* Compiler (nftables): an IPv6 network with a /0 netmask is reported as a likely mistake, as on iptables.
* Compiler (nftables): dropping TCP sessions that were open before a firewall restart no longer drops legitimate new connections along with them.
* Compiler (nftables): firewalls that log through NFLOG with one of the IP or TCP option logging settings enabled produce a ruleset that loads.
* Compiler (nftables): generated rules carry a counter, so `nft list ruleset` shows per-rule hit counts as the iptables output does.
* Compiler (nftables): IP services that match a DSCP value produce a ruleset that loads. A match on the legacy ToS byte, which nftables cannot express, is reported.
* Compiler (nftables): IPv6 NAT rules produce a ruleset that loads.
* Compiler (nftables): logging of invalid packets uses the debug level and the configured NFLOG group. Under a packet flood those messages reached the console.
* Compiler (nftables): long log prefixes are no longer truncated, so log parsers keyed on the full prefix match again.
* Compiler (nftables): NAT rules that match a MAC address where that cannot work drop the match with a warning, as on iptables, instead of translating nothing.
* Compiler (nftables): NAT rules that name a host or a firewall with more than one address cover all of its addresses. Only the first one was translated or matched, so the rest of the traffic passed untranslated.
* Compiler (nftables): NAT rules that translate only the port perform the translation instead of letting the traffic pass untranslated. Combined source and destination translation with a port works as well.
* Compiler (nftables): NAT rules with a negated original source or destination produce a ruleset that loads.
* Compiler (nftables): on bridging firewalls, rules to a broadcast, multicast or on-link address no longer generate a spurious extra rule.
* Compiler (nftables): outbound rules with a negated source that are directed at a firewall address are no longer silently dropped.
* Compiler (nftables): rule shadowing detection no longer reports false warnings for rules with a negated source or destination ([#136](https://github.com/Linuxfabrik/firewallfabrik/issues/136)).
* Compiler (nftables): rules and NAT rules that match an ICMPv6 service with no specific type produce a ruleset that loads.
* Compiler (nftables): rules and NAT rules that negate their service match the opposite of it. For ICMP and IP services they did exactly the reverse of what the rule says.
* Compiler (nftables): rules that match a DNS name beginning with a digit produce a ruleset that loads.
* Compiler (nftables): rules that match a single TCP flag produce a ruleset that loads.
* Compiler (nftables): rules that match a Tag Service whose tag carries a mask produce a ruleset that loads.
* Compiler (nftables): rules that match TCP flags match those flags instead of all TCP traffic.
* Compiler (nftables): rules that tag packets and save the tag to the connection do both. The tag was lost as soon as the connection was established.
* Compiler (nftables): rules that tag packets or assign a traffic class work instead of aborting the compile ([#122](https://github.com/Linuxfabrik/firewallfabrik/issues/122)).
* Compiler (nftables): rules with a negated interface match every other interface. An anti-spoofing rule did the exact opposite of what it says.
* Compiler (nftables): rules with a rate limit are rate-limited instead of passing all traffic.
* Compiler (nftables): rules with the Accounting action count the traffic they match, in a counter `nft list counters` reads back.
* Compiler (nftables): rules with the Pipe action hand the packet to userspace instead of aborting the compile.
* Compiler (nftables): stopping the generated script reports success. It reported a failure on nearly every firewall, which systemd units and Ansible tasks act on.
* Compiler (nftables): the "error" and "warning" log levels produce a ruleset that loads.
* Compiler (nftables): the "random" and "persistent" NAT options reach the generated ruleset instead of being dropped.
* Compiler (nftables): the logging rate limit can be set again in the firewall settings.
* Compiler (nftables): the NFLOG "Copy range" and "Queue threshold" settings reach the generated ruleset instead of being ignored.
* Compiler (nftables): time restrictions that run past midnight match that night instead of nothing at all.
* Compiler (nftables): time-restricted rules fire at the same hours as on iptables, and the "use kernel timezone" setting is honoured. The weekday is always matched in UTC, which a rule restricting both now warns about.
* Compiler (nftables): translating a whole network maps the addresses one to one, as on iptables, instead of picking an arbitrary one per connection.
* Compiler (nftables): translating the source to a PPP or DHCP interface masquerades, as on iptables, instead of using an address the traffic never leaves by.
* GUI: the "Logging limit:" label in the nftables firewall settings is no longer greyed out, which suggested the setting had no effect.
* GUI: the "Use kernel timezone instead of UTC" tooltip in the nftables firewall settings describes what nftables does instead of naming an iptables version requirement.
* GUI: the firewall settings offer the same "Default action on Reject" choices as the per-rule action editor, so a firewall imported with "ICMP admin prohibited" or "ICMP protocol unreachable" keeps it.
* Installing the GUI variant (`firewallfabrik[gui]`) no longer fails to resolve its Qt dependency.


## [v1.9.0] - 2026-07-12

### Added

* CLI: `fwf-upgrade` converts a Firewall Builder `.fwb` file and brings an older `.fwf` file to the current format without opening the GUI. Given a directory it processes everything below it, and `--dry-run` lists what it would touch ([#132](https://github.com/Linuxfabrik/firewallfabrik/issues/132)).


## [v1.8.1] - 2026-07-01

### Fixed

* GUI: FirewallFabrik no longer crashes when the object tree is rebuilt while a search is open.


## [v1.8.0] - 2026-06-29

### Added

* Compiler (iptables, nftables): the "Accept ICMP redirects" and "Accept source-routed packets" hardening settings also apply to IPv6, not only to IPv4.
* Compiler (nftables): the kernel-hardening and conntrack tuning settings from the firewall's Host OS settings are applied by the generated script. They were honoured on iptables only, and the fields are now editable for nftables firewalls.
* Documentation: the user guide explains the `.fwf` file structure and maps every firewall setting in the GUI to its key, so the file can be edited for bulk changes and automation.

### Deprecated

* Host OS setting "TCP fack": the Linux kernel dropped FACK loss detection, so the setting has no effect on any supported release. It is greyed out and no longer written to the generated script.

### Fixed

* Compiler (iptables): the conntrack tuning settings (maximum connections, hash table size, liberal TCP tracking) reach the kernel instead of being ignored.
* Compiler (nftables): switching a firewall from iptables to nftables removes the leftover iptables rules on activation. They could shadow the new rules, so a changed rule appeared to have no effect even after a reboot.
* Compiler (nftables): the backup SSH access rule of the "block" action is generated. It never appeared, which could lock an administrator out while blocking a firewall.
* Compiler (nftables): the IPv4 and IPv6 forwarding commands are indented consistently in the generated script.
* Documentation: corrected user-guide statements that no longer matched the application, among them bridge configuration, IPv6 address ranges, what the "stop" action does, and several dialog, button and menu labels.
* GUI: the "Update Standard Library" preview lists the affected firewalls and rules under an expanded row, which appeared blank.


## [v1.7.0] - 2026-06-18

### Added

* Object tree context menu: "Collapse", "Collapse All", "Expand" and "Expand All". The plain variants toggle the clicked node, the "All" variants every node below it.

### Changed

* User guide: expanded the nftables introduction with background on what nftables changed over iptables.
* User guide: Linux desktop icons can be installed without a custom theme index file.
* User guide: revised "Migrating from Firewall Builder" with explicit platform version coverage, clearer columns, a corrected categorisation and a caveat on cluster support.

### Fixed

* GUI: editing a standalone IPv4 or IPv6 address no longer shows a Netmask field. It never affected the generated firewall and only produced confusing values; on an interface address, where it matters, it still appears.
* GUI: selecting a predefined Any object shows what Any matches in a rule, instead of an editable form with meaningless values such as address 0.0.0.0.


## [v1.6.0] - 2026-05-07

### Added

* Compiler (iptables): the "Use kernel timezone" setting is honoured on time-restricted rules, so their times are read in the kernel timezone instead of UTC.
* Compiler (iptables, nftables): the "Log IP options", "Log TCP options" and "Log TCP sequence numbers" settings are honoured on logging rules. A per-rule setting overrides the firewall-wide default.

### Changed

* GUI: File > Open Recent tells entries apart by their differing path segments; the full path stays in the tooltip.

### Fixed

* GUI: a greyed-out checkbox in the firewall settings explains why it is disabled instead of repeating its label.
* GUI: the iptables and nftables firewall settings no longer mark options as unsupported that the compiler does honour, among them "Drop new TCP sessions without SYN", "Log all rules" and "Clamp MSS to MTU".
* GUI: the nftables firewall settings grey out the options the nftables compiler does not implement. They accepted clicks and had no effect.


## [v1.5.1] - 2026-05-07

### Fixed

* GUI: opening the Platform Settings dialog of an nftables firewall no longer crashes.

### Security

* CI: scoped the `GITHUB_TOKEN` permissions of the dependabot auto-merge workflow to the job level, matching the other Linuxfabrik workflows.


## [v1.5.0] - 2026-04-29

### Added

* File > Reload has the keyboard shortcut Ctrl+R.
* Install options dialog: a password or passphrase field and a "Remember passwords" checkbox, so a passphrase-protected SSH key or password authentication works from the dialog. Passwords are kept in memory for the session and never written to disk ([#72](https://github.com/Linuxfabrik/firewallfabrik/issues/72)).
* Object tree: Policy, NAT and Routing rule sets show their rule count, updated as rules are added, deleted or pasted.
* Renaming a firewall, host or interface that has child objects offers to rename the children along the standard naming scheme, as Firewall Builder does.

### Changed

* Address ranges that cover an exact CIDR block are compiled to the short CIDR form, so the range match is only used where it is needed.
* Dynamic Groups combine their criteria with AND instead of OR. This closes a class of overly permissive rules, where a group with several criteria used as source or destination widened the rule unintentionally. A per-group selector switches back to OR, and groups imported from a `.fwb` file keep OR ([#82](https://github.com/Linuxfabrik/firewallfabrik/issues/82)).
* Interface context menu no longer offers "New Attached Networks" or "New Failover Group". Both produced broken objects; they return with the cluster support ([#78](https://github.com/Linuxfabrik/firewallfabrik/issues/78), [#84](https://github.com/Linuxfabrik/firewallfabrik/issues/84), [#85](https://github.com/Linuxfabrik/firewallfabrik/issues/85)).
* iptables and nftables firewall settings: the Compiler tab lists its five fields in one aligned grid, and two inline hints moved into the tooltips of the fields they describe.
* iptables, nftables and Linux settings: an empty text field no longer shows its default as placeholder text, which made it look pre-filled and disabled. Only fields with a real hint still show one.
* Policy and NAT action menus no longer offer "Branch". It lost the branch target silently and compiled to an undefined result; it returns with full branch support ([#83](https://github.com/Linuxfabrik/firewallfabrik/issues/83), [#90](https://github.com/Linuxfabrik/firewallfabrik/issues/90)).

### Fixed

* `fwf-ipt --all` and `fwf-nft --all` skip firewalls flagged inactive, as Firewall Builder does. Naming one explicitly still compiles it ([#89](https://github.com/Linuxfabrik/firewallfabrik/issues/89)).
* Address ranges used as a destination in iptables policy rules are matched instead of being silently dropped, which made those rules less restrictive than intended.
* Clipboard shortcuts work reliably for objects in the tree. Clicking any widget outside the tree silently rerouted them.
* Compile and Install dialogs show the firewall icon next to the firewall name, so both views line up with the object tree.
* Compile Firewalls: a compiler that crashed while writing its output file is reported as failed and exits non-zero, instead of "compiled successfully".
* Compiler (iptables): a firewall used as source or destination expands to one rule per own address, so an anti-spoofing rule covers the other own addresses too. They were silently missed.
* Compiler (iptables): mangle rules that have a direction but no specific interface carry that direction.
* Compiler (iptables): rules that match "any ICMP type", and rules that match a specific ICMPv6 type, load on older ip6tables releases as well.
* Compiler (iptables): temporary chain names are stable across compilations, so recompiling an unchanged policy produces a byte-identical script and CI pipelines and `git diff` no longer see phantom changes.
* Compiler (iptables): the "TCP fin timeout" and "TCP keepalive interval" settings left at their default are no longer pushed into the kernel as 0, which would have closed TIME_WAIT sockets instantly and disabled keepalive spacing.
* Compiler (iptables): the "Use numeric log levels" setting is honoured on logging rules.
* Compiler (iptables): the automatic MSS clamping rule sits in the forward chain, and is left out where IP forwarding is off or the target cannot express it.
* Compiler (iptables): with "Use iptables-restore" the rules are written in the form iptables-restore accepts. It rejected the script, so either no rule was applied at all or the firewall fell back to overly permissive defaults ([#77](https://github.com/Linuxfabrik/firewallfabrik/issues/77)).
* Compiler (iptables, nftables): "Assume firewall is part of 'any'" is respected when splitting a rule on a network that contains one of the firewall's own addresses, so no extra rules appear that Firewall Builder would not emit.
* Compiler (iptables, nftables): a custom service that has code for the target platform is recognised instead of aborting the compile ([#71](https://github.com/Linuxfabrik/firewallfabrik/issues/71)).
* Compiler (iptables, nftables): a firewall interface with address 0.0.0.0 or :: or with netmask /0 aborts with a clear error instead of producing dead rules.
* Compiler (iptables, nftables): a rule whose source is an address range overlapping a firewall interface no longer generates a second rule that can never match.
* Compiler (iptables, nftables): a shadowing warning is reported once per compilation instead of once per variant the rule expands into.
* Compiler (iptables, nftables): a single-address range holding an IPv4 address produces an IPv4 rule. All of them were forced into the IPv6 output, which silently dropped those rules.
* Compiler (iptables, nftables): Custom, Tag and User Services reach the generated rules. Their code was dropped, so an established/related rule became a bare accept that let all traffic through ([#72](https://github.com/Linuxfabrik/firewallfabrik/issues/72)).
* Compiler (iptables, nftables): IPv6 reject rules use the IPv6 reject types. The IPv4 names were refused, so the IPv6 script failed to load on the firewall.
* Compiler (iptables, nftables): NAT rules using an address range that spans several CIDR blocks produce a ruleset that loads.
* Compiler (iptables, nftables): no more spurious shadowing warnings for rules whose source or destination is "any".
* Compiler (iptables, nftables): no more spurious shadowing warnings for TCP services that inspect TCP flags, which were treated as "any TCP". This was most visible on policies imported from Firewall Builder ([#73](https://github.com/Linuxfabrik/firewallfabrik/issues/73)).
* Compiler (iptables, nftables): rules that use an address range land in the right chains. This produced overly permissive masquerading and missing rules before.
* Compiler (iptables, nftables): rules to a broadcast or multicast address are filtered as traffic to the firewall itself, and the reverse for outbound rules.
* Compiler (iptables, nftables): the address family of a custom service imported from a `.fwb` file is honoured, so an IPv4-only service is left out of the IPv6 ruleset instead of producing a misleading error and an unmatched drop.
* Compiler (iptables, nftables): the informational "Adding of virtual address for address range is not implemented" message is gone. The generated rules were already correct.
* Compiler (nftables): a Reject rule with "TCP RST" on non-TCP services falls back to the configured reject action with a warning, and a rule mixing both is split. The non-TCP part never matched.
* Compiler (nftables): an automatic MSS clamping rule is generated when "Clamp MSS to path MTU" is set, matching iptables.
* Compiler (nftables): policy rules whose interface has no address of the address family being compiled are left out, matching iptables.
* Compiler (nftables): Reject rules whose service is "any" are split, so TCP gets a reset and every other protocol the configured action.
* Compiler (nftables): rules that use a User Service where it cannot take effect are left out with a warning, matching iptables.
* Compiling a firewall whose outbound rules target an address range no longer aborts with an internal error.
* Copying an interface onto another interface creates a subinterface, as Firewall Builder does. Copying it onto a firewall or host adds it as a top-level interface.
* Drag and drop from the object tree shows the item's icon on the cursor, with a count badge for a multi-selection. Wayland does not render it (Qt6 limitation).
* Duplicating an address under an interface places the copy in the canonical group, as Firewall Builder does.
* File > Reload works for native `.fwf` files and imported `.fwb` files alike; it silently did nothing.
* Generated firewall script: "stop" resets the built-in chain policies to ACCEPT after flushing. They stayed at DROP, so the firewall kept blocking all traffic after a stop and had to be reset by hand.
* Generated firewall script: every action checks for the tool it needs and aborts with a clear message. Only "start" was guarded, so the other actions failed silently and "status" claimed the firewall was not configured when the tool was merely absent.
* Install rules: the destination path on the firewall is no longer built by concatenating the local output path with the remote directory, which produced a duplicated path and aborted the copy. The three path fields are now described separately in their tooltips ([#72](https://github.com/Linuxfabrik/firewallfabrik/issues/72)).
* Object tree: renaming a device and accepting the rename prompt refreshes the renamed child objects too. They kept their old names until the file was reloaded.
* Recent files menu: entries pointing to files that no longer exist are dropped at startup, so clicking them no longer fails.

### Removed

* Dropped the legacy "Use ULOG" firewall option. The Linux kernel removed the ULOG target years ago; a `.fwb` file that still carries it is migrated to LOG on import.
* The nftables firewall settings no longer expose iptables-only options the nftables compiler cannot act on. They stay available under iptables.

### Security

* The Firewall Builder `.fwb` importer is hardened against malformed and malicious input files. Regular files import unchanged.


## [v1.4.6] - 2026-04-09

### Added

* User guide: "When to Use the Stateless Option" best practices section covering default deny rules, anti-spoofing rules, loopback rules and DHCP broadcasts

### Changed

* Compile dialog: compiler detail output (ruleset names, etc.) shown in small gray monospace text; each firewall block visually grouped with an underlined heading
* Install dialog: SSH output (banners, MOTD, script output) displayed in small gray monospace text, indented to distinguish it from installer status messages

### Fixed

* All popup dialogs now have a visible border on GNOME/Wayland
* HTML entity `&#x27;` no longer appears instead of apostrophes in the compile log
* Options column in the policy editor now shows the "Options" icon when non-default rule options are set (e.g. stateless, limit, connlimit, hashlimit); also works for NAT and Routing rules
* Rule options icon for `stateless` was missing because `has_nondefault_options()` did not check for it


## [v1.4.5] - 2026-04-09

### Changed

* Compile dialog: "Compile Firewalls" moved from an in-dialog label to the window title bar; firewall sidebar width adapts dynamically to content
* Compile dialog: compiler detail output (ruleset names, etc.) is shown in small gray text; each firewall block is visually grouped with an underlined heading
* Compile dialog: progress column shows "Compiled with Warnings" (orange) or "Compile Error" (red) instead of generic status text

### Fixed

* Compiler warnings (e.g. "Making rule stateless because it matches ICMPv6") no longer cause the compilation to be reported as failed; they are now shown as orange warnings in the GUI and CLI while the exit code remains 0
* Delete key on selected elements in the policy editor was silently ignored due to ambiguous keyboard shortcut registration between Edit menu and Rules menu
* Double-clicking an Options, Action or Comment cell in the policy editor no longer scrolls back to the first rule
* Fix `--require-hashes` pip installs in CI workflows by using pinned versions instead
* Generated iptables shell scripts are now fully POSIX sh compliant and pass shellcheck without warnings: proper variable quoting, `read -r` for backslash safety, `local` replaced with plain variables, backticks replaced with `$()`, `test "X$var"` idiom modernized ([#36](https://github.com/Linuxfabrik/firewallfabrik/issues/36))
* Scrollbars in the object tree and policy editor are now visible (removed custom QSS scrollbar styling that was invisible on some desktop themes)


## [v1.4.4] - 2026-04-08

### Fixed

* Custom Service editor: Platform dropdown always reset to nftables instead of remembering the last selection ([#61](https://github.com/Linuxfabrik/firewallfabrik/issues/61)).
* Sporadic SIGSEGV crash when rebuilding the object tree after compilation or when closing/creating files ([#57](https://github.com/Linuxfabrik/firewallfabrik/issues/57)).


## [v1.4.2] - 2026-04-08

### Fixed

* Images not loading on the MkDocs documentation site due to broken relative paths in HTML image tags.
* Object tree attribute column too narrow on first use when "Show object attributes in the tree" is enabled ([#60](https://github.com/Linuxfabrik/firewallfabrik/issues/60)).


## [v1.4.1] - 2026-04-08

### Added

* Documentation on how to install Release Candidate (RC) versions
* MkDocs-based documentation site, deployed automatically to GitHub Pages

### Changed

* Unify CONTRIBUTING with Linuxfabrik standards
* Update pre-commit hooks to latest versions

### Fixed

* `pyside6-rcc` not found when installed via `uv tool install` because the tool is inside the isolated virtual environment and not on the user's PATH ([#58](https://github.com/Linuxfabrik/firewallfabrik/issues/58)).
* GUI failed to start on Wayland-only systems (e.g. GNOME without X11) because Qt defaulted to the xcb platform plugin ([#58](https://github.com/Linuxfabrik/firewallfabrik/issues/58)).
* Improved Wayland detection to also cover systems where only wayland-egl or wayland-brcm platform plugins are available ([#58](https://github.com/Linuxfabrik/firewallfabrik/issues/58)).
* Pre-compiled Qt resource file (`.rcc`) was written to the wrong directory during package build, causing unnecessary runtime recompilation.
* Sporadic SIGSEGV crash when opening a rule editor (action, comment, direction, metric, options) while another editor had unsaved changes ([#57](https://github.com/Linuxfabrik/firewallfabrik/issues/57)).


## [v1.4.0] - 2026-03-29

### Added

* "Flush entire ruleset" option for both iptables and nftables. When disabled, FirewallFabrik only manages its own tables/chains (e.g. `fwf_filter`, `fwf_nat` for nftables or `fwf_INPUT`, `fwf_FORWARD` for iptables), leaving rules created by other tools like Docker, CrowdSec and fail2ban untouched.

### Changed

* Default output file name changed from firewall object name to `fwf.sh`.
* Default script directory on the firewall changed from `/etc/fw` to `/etc`.
* Default table/chain prefix changed from `linuxfabrik` to `fwf`.

### Fixed

* `RETVAL` variable is now initialized at script start and set to `1` for invalid arguments.
* `stop_action` in generated iptables scripts now keeps chain policies at DROP instead of setting ACCEPT, preventing the server from being completely open after stop.
* Application no longer crashes with a segmentation fault when pressing Ctrl+C in the terminal.
* Coexistence mode: `status` command now correctly detects whether the firewall is active, even when other tools like Docker create additional chains.
* Coexistence mode: `stop` command now properly removes all FirewallFabrik chains, including sub-chains with hash-based names (e.g. `fwf_C...`) that were previously left behind ([#42](https://github.com/Linuxfabrik/firewallfabrik/issues/42)).
* Coexistence mode: `stop` command now properly removes FirewallFabrik's chains and jump rules on all systems, including those using the iptables-nft backend.
* Coexistence mode: `stop` command now restores chain policies to ACCEPT so that rules from other tools (Docker, CrowdSec, fail2ban) keep working after stopping the firewall.
* Compiler error and warning messages now show the rule position number instead of the color label.
* Compiler no longer rejects TCPService objects with a string `'False'` value for the `established` option.
* Compiler now generates IPv6 rules (ip6tables / nftables inet) based on the rule set's address family setting ("IPv4 and IPv6") instead of requiring IPv6 addresses on the firewall's interfaces ([#42](https://github.com/Linuxfabrik/firewallfabrik/issues/42)).
* Extra leading whitespace in generated iptables scripts from inline configlet `{{if}}` blocks removed.
* Generated iptables scripts now abort on `script_body` failure instead of continuing with an incomplete ruleset.
* Generated scripts use `command -v` instead of non-POSIX `which` for checking program availability.
* Harmless Qt/Wayland text-input warnings suppressed during GUI startup.
* IPv6 address and network dialogs now accept prefix lengths 0-128 instead of 1-127 ([#50](https://github.com/Linuxfabrik/firewallfabrik/issues/50)).
* Main window border is now clearly visible on GNOME/Wayland.
* Test infrastructure: expected output files are now also regenerated for firewalls with compiler warnings.


## [v1.3.0] - 2026-03-17

### Added

* `Alt+Return` keyboard shortcut opens the editor for the selected object (same as double-click).
* Advanced Interface Settings dialog to configure device type (ethernet, VLAN, bridge, bonding), VLAN ID, STP and bonding parameters.
* Appearance tab in Preferences — customize fonts for rules, tree and compiler output; toggle direction/action text, comment clipping and toolbar labels.
* Bridge interface configuration support for iptables and nftables using iproute2 (`ip link`).
* Bridge port interfaces are detected automatically from the parent interface type.
* Installer tab in Preferences — configure SSH/SCP paths, timeout and password caching for the built-in policy installer.
* Rules menu: insert, move, copy, cut, paste, remove, disable and enable rules directly from the menu bar.
* Tooltips on all widgets in the platform settings dialogs and the interface editor.
* VLAN sub-interface name validation — warns when the name does not match the parent interface.

### Changed

* "Unprotected interface" checkbox removed from the interface editor (not applicable to iptables/nftables).
* About dialog: Linuxfabrik credit visually separated with homepage link (https://www.linuxfabrik.ch).
* Application icon uses PNG at multiple sizes for Wayland compatibility; window icon set via .ui file.
* Default label colors use the Solarized palette throughout; "Purple" renamed to "Cluster", "Gray" renamed to "Maintenance".
* Interface autoconfigure now also runs when opening the editor, not only on save.
* Platform settings dialogs: Script tab shows inline descriptions for each option; Help buttons removed; dialog size reduced.
* Policy rule table borders now match the fwbuilder look (native headers, subtle cell borders).
* Removed XCB/XWayland fallback; fwf runs natively on Wayland.
* Timestamps removed from generated shell scripts to ensure idempotent deployments.

### Fixed

* Address containment: AddressRange objects were incorrectly treated as "any" address by the shadowing detector.
* Shadowing detection now produces warnings instead of aborting the compilation.


## [v1.2.0] - 2026-03-17

### Added

* Clickable compile log errors scroll to the relevant firewall section (closes #15).
* Cluster Member Management dialog to add/remove firewalls and view interface mappings (closes #26).
* File Properties dialog showing file path, size, and object counts (closes #29).
* Full Firewall Builder compiler parity for iptables and nftables (~130 rule processors ported).
* Import Addresses from File via Tools menu (closes #12).
* Inspect Rules showing all rules referencing the selected object (closes #28).
* Interface name autoconfiguration guesses type and VLAN ID from name patterns.
* Library Export to a separate `.fwf` file (closes #27).
* Library Import from `.fwf` or `.fwb` files.
* NFLOG logging target support for iptables and nftables (closes #18).
* nftables load balancing, address set merging, and separate shadowing pass (closes #22, #23, #24).
* Policy rules now use Preferences defaults for logging, stateful inspection, action, and direction.
* Preferences dialog with Restore Defaults, DNS Name, Address Table, Policy Rules, and Interface tabs.
* Standard service library: Bareos, Keycloak, Kibana, Libvirt, Logstash, OpenSearch.

### Changed

* Generated iptables scripts now run `nft flush ruleset` on systems where `nft` is available.
* Timestamp format in generated scripts changed to ISO 8601.

### Fixed

* "Advanced Interface Settings" button documented as intentionally disabled for iptables/nftables (closes #13).
* False-positive shadowing errors caused by analysis injecting rules into the main pipeline.
* Hardcoded version in generated iptables scripts replaced with the actual package version.
* MAC address edits were silently ignored (fixes #14).
* Multiport rules were broken: TCP flag check incorrectly matched all TCP services (fixes #21).
* Opening objects for editing no longer marks the file as modified when nothing changed (fixes #25).


## [v1.1.0] - 2026-03-16

### Added

* DiffServ (DSCP/TOS) matching for the nftables compiler (`ip dscp` / `ip tos`).
* DSCP symbolic class names (`AF11`, `EF`, `CS3`, etc.) now generate `--dscp-class` in iptables output, matching Firewall Builder behavior.
* Fragment matching (`-f` / `-m frag --fragmore`) and IPv4 option matching (`-m ipv4options`) in the iptables filter compiler (previously only present in the NAT compiler).
* Router-alert IP option (`--ra` / `--flags router-alert`) support in both iptables filter and NAT compilers.
* Tooltips for all IPService dialog fields (protocol number, DSCP, TOS, IP options, fragments).
* Version-aware `ipv4options` module formatting: old module (`--lsrr`, `--ra`) for iptables < 1.4.3, new module (`--flags lsrr,router-alert,...`) for >= 1.4.3.

### Changed

* DiffServ default changed from TOS to DSCP (the modern standard).
* DiffServ radio buttons unselected by default when no code is set; input field disabled until DSCP or TOS is chosen.
* Input widget borders use `palette(dark)` instead of `palette(mid)` for better visibility.

### Fixed

* Boolean flags stored as string `'False'` (truthy in Python) now stored as native booleans.
* DiffServ data keys now consistent across compilers and shadow detection.
* ICMP type/code matching in NAT rules now reads from the correct attribute.
* Rule shadowing false positives for IPService objects (e.g. VRRP) fixed.
* TagService data key inconsistency between dialog and display fixed.
* TCP flags in iptables compiler now read from ORM attributes instead of pre-formatted strings.


## [v1.0.1] - 2026-03-11

### Fixed

* Platform YAML defaults not included in pip-installed packages (missing `MANIFEST.in` entry).


## [v1.0.0] - 2026-03-08

### Added

* CLI compilers (`fwf-ipt`, `fwf-nft`) accept multiple firewall names and `--all` flag; database is loaded once for all firewalls.
* Collabora Online, Icinga, Nextcloud notify_push and WinRM added to the standard library.
* Compile time intervals and clean up time dialog.
* Confirm-delete dialog when deleting objects that are still in use.
* DNS "Resolve Name" button implemented for IPv4 and IPv6 address dialogs.
* DynamicGroup editor with criteria table and matched-objects preview.
* Example files shipped with the distribution.
* File > Reload action to re-read the current file from disk.
* FreeIPA service group added to the standard library.
* MIME type definitions for `.fwf` and `.fwb` files for file manager integration.
* NAT and Routing rule display support with title bar dirty-state indicator.
* Parallel compilation in the GUI: multiple firewalls compile concurrently using up to N CPU cores, with ordered log output.
* Platform and OS option defaults defined in YAML as single source of truth, replacing scattered hardcoded dicts.
* Settings dialogs now show tooltips and placeholder defaults from the YAML schema.
* Subfolder paste, drag & drop, and nested object creation in the object tree.
* System theme icons (Breeze, Adwaita, etc.) for toolbar and menu actions, with QRC fallback.
* Title labels on MDI rule set panels and Del key support for deleting rules.
* Undo stack entries prefixed with the device name for clarity.
* Window menu and automatic opening of firewall Policy on file load.

### Fixed

* `.fwb` imports allowed to compile and install without requiring a prior save.
* Clipboard router now correctly routes Ctrl+C/X/V to focused text widgets.
* Compiler option lookup (`get_option`) now raises `KeyError` on unknown keys, catching typos at the earliest possible moment; all inline Python fallbacks removed in favour of YAML defaults.
* Context menus and sub-interfaces aligned with fwbuilder behavior.
* Dead menu entries removed (File Compare, SNMP Discovery, Policy Import, Library Import/Export, Print, Help Contents/Index).
* DynamicGroup, AddressTable and DNSName now allowed in rule src/dst cells.
* Find & Replace scope, tree filter, element display, and MDI refresh.
* Focus moves to next element in a rule cell after deleting an object.
* ICMP type/code now read from the codes field instead of data.
* Keywords renamed to Tags in context menus.
* Last-active rule set persisted by name instead of UUID for stability across imports.
* Legacy Firewall Builder compiler paths (`fwb_ipt`, `fwb_nft`) detected during `.fwb` import; a dialog offers to clear them so FirewallFabrik uses its built-in compiler.
* Linux host settings now save under canonical `linux24_conntrack_*` keys matching the compiler.
* Lock/Unlock menu actions wired up to tree selection.
* MDI views refresh on object rename; undo descriptions are now human-readable.
* Model class name used instead of `.type` in `duplicate_object`.
* Netmask shown in tree when editing an address under an interface.
* New objects created via the toolbar menu now land in the selected custom folder.
* Nftables compiler now correctly generates `tcp flags != syn ct state new drop` rules when `accept_new_tcp_with_no_syn` is disabled (was reading a non-existent key).
* Object deletion fixed: str-vs-UUID type mismatch in where-used reference queries.
* Object tree auto-selects the Policy item when opening a file.
* ORM objects flushed before raw `rule_elements` INSERT to avoid integrity errors.
* Output pane context menu shows Ctrl+C and Ctrl+A shortcuts.
* Parent firewall `lastModified` timestamp updated on child/rule/shared-object edits.
* Readonly flag passed to tree items with updated lock icons.
* Rule shadowing detection enabled by default; error messages include rule position numbers.
* Time dialog uses YYYY-MM-DD date format and sensible defaults.
* Title bar double-click on Wayland now works (XCB fallback).

### Changed

* Decouple GUI components with ClipboardStore, PolicyViewBridge, and focus registration.
* Extract ClipboardRouter, EditorManager, and RuleSetWindowManager from FWWindow.
* Extract context-menu builders from PolicyView into a dedicated module.
* Extract TreeActionHandler from ObjectTree.
* Modernize UI with comprehensive QSS stylesheet.
* Object tree rewritten into 4 focused modules.
* Replace tree clipboard global with instance attribute and add paste validation.


## [v0.5.0rc1] - 2026-02-13

### Added

* Center compile dialog on screen and persist its geometry.
* CIDR notation parsing in IPv4/IPv6 editor dialogs and editor breadcrumb.
* Firewalls needing recompilation shown in bold in the object tree.
* Highlight only the clicked cell in rule view and protect default Any elements.
* Input validation and widget constraints for all editor dialogs.
* RuleSet editor dialog for Policy, NAT and Routing.
* Show asterisk in title bar when file has unsaved changes.

### Fixed

* Address range end field auto-filled when start field loses focus.
* Bool-coerced inactive flag from XML loader handled correctly.
* Compile, Install and Save actions disabled when no file is loaded.
* Compiler/installer remote paths and file names corrected.
* Context menu actions deferred to prevent SIGSEGV on tree clear.
* Default Qt icon replaced with the FirewallFabrik app icon.
* Deprecated Qt5 margin property removed from .ui files.
* Host OS Settings options disabled for unsupported nftables features.
* Platform Settings options disabled for unsupported compiler features.
* Qt5 signal/slot mismatch in the find panel .ui file corrected.
* Skip Any sentinel objects in rule element display.
* Warn before overwriting existing .fwf when saving an imported .fwb.

### Changed

* Erroneous QSS styling removed.
* Include .qss files in build output.


## [v0.5.0b1] - 2026-02-13

Initial public beta pre-release.

### Added

* Compile and install workflow for iptables and nftables platforms.
* Ctrl+Shift+N shortcut for File > New Object File.
* Ctrl+Shift+S shortcut for File > Save As.
* Detailed object tooltips ported from fwbuilder to the rule editor.
* File > Close (Ctrl+F4) to close the current document.
* Group dialog with drag & drop support.
* Host wizard dialog ported from fwbuilder.
* Library folder structure with nested group placement.
* MDI rule set windows with multi-select drag, clipboard, delete and context menu.
* Modernized Qt6 appearance with Fusion style and central stylesheet.
* nftables settings dialog.
* Object tree with Delete context menus and New [Type] for group-based folders.
* Panels hidden when no database file is loaded.
* Resource compilation from .qrc at build time.
* Restore last active object and MDI rule set when reopening a file.
* Rule number column display and platform combo defaults.
* Service library expanded with Wikipedia multi-service ports.
* Single-rule compile for the correct platform, with error for unsupported platforms.

### Fixed

* Accept new TCP with no SYN option corrected.
* Firewall modified timestamp updated when changing host/platform settings.
* Flush pending editor changes before save/close/switch.
* IPv4/IPv6 order option corrected.
* Object tree strikethrough and MDI titles refreshed on inactive toggle.
* Stub slots added for unimplemented .ui connections; unused UI elements disabled.

### Changed

* Fixture database caching with sqlite3 serialize/deserialize for faster tests.


[Unreleased]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.9.0...HEAD
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
