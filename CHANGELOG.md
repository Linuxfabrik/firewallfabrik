# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

### Changed

* FirewallFabrik now runs on Python 3.11 and newer; it previously required Python 3.14. This lets it install on current enterprise and desktop distributions without a custom Python build.

### Fixed

* Compiler (iptables): a firewall that does not pin a specific iptables version is now compiled for current iptables instead of for the oldest release ever supported. Rules with a negated address or interface were written as `-s ! 192.0.2.0/24`, a form iptables has rejected since 1.4.3, so those rules failed to load. The generated script now also waits for the iptables lock, uses the `conntrack` match instead of the obsolete `state` match, and honours the "use ipset" setting, all of which were tied to the assumed version as well. Firewalls that do pin a version are unaffected.
* Compiler (iptables): a bridging firewall whose rules name an interface as a destination now compiles. The check that decides whether a destination is a broadcast or multicast address asked the interface object for an address it does not have, which ended the compile with an internal error and left no script behind at all. The nftables compiler already guarded against this.
* Compiler (iptables): a firewall with routing rules now generates a working script. The first routing command was appended to the last iptables command instead of starting on its own line, which broke both: the packet filter refused the rule and the route was never added.
* Compiler (iptables): a NAT rule whose translated address the compiler cannot determine is now reported as an error and left out of the generated script, instead of emitting `-j SNAT`, `-j DNAT` or `-j NETMAP` without the address those targets insist on. iptables refuses such a rule and the activation script stops there, leaving the firewall half-loaded. This happens for a source translation to a dynamic interface, whose address is only known at run time, and for a network translation whose target network cannot be resolved.
* Compiler (iptables, nftables): a firewall with "Add rules to permit IPv6 Neighbor Discovery" enabled now generates those rules. The compiler looked the setting up under a name no firewall file ever uses, so it always read the default "off" and a dual-stack firewall that drops by default silently lost IPv6 connectivity. The nftables compiler, which did not implement the setting at all, now generates the rules as well.
* Compiler (iptables): a rule with a time restriction now uses the option names the pinned iptables understands. The weekday list was always written as `--weekdays`, which the time module only learned in 1.4.0 (it is `--days` before that), and `--kerneltz` was emitted for releases older than 1.4.11, which do not know it. Both made the rule fail to load on those targets.
* Compiler (iptables): a firewall pinned to "1.2.5 or earlier" or to "1.2.6 to 1.2.8" is compiled for that iptables again. Both settings are stored under a name that is not a plain version number, and the compiler read them as if they were newer than every release there is. Such a firewall got the modern syntax throughout: the `conntrack` match, extrapositioned negation (`! -s ...`), a lock wait, and the current spelling of the time and IP-options matches, none of which those releases understand.
* Compiler (iptables): a firewall that uses iptables-restore now writes its log prefixes correctly. The quotes around the prefix were left unescaped inside the `echo` line that builds the restore file, so the shell swallowed them: every log message lost the space at the end of its prefix and ran into the packet data (`RULE 0 -- DENYIN=eth0 ...`), which breaks log parsers. A prefix containing shell syntax was interpreted by the shell as well.
* Compiler (iptables): a rate limit iptables cannot express is now reported as an error instead of producing a script that stops at activation time. The limit match tops out at 10000 per time unit and its burst at 10000; a higher value made iptables refuse the rule with "Rate too fast" or "out of range", leaving the firewall half-loaded. nftables has neither ceiling and is unaffected.
* Compiler (iptables): a rule set or branch whose name yields a chain name iptables cannot create is now reported as an error instead of producing a script that fails at activation time. Besides a name longer than 28 characters, this now also catches a name containing a space and one starting with "-" or "!", both of which iptables refuses as well. nftables has no such limits and is unaffected.
* Compiler (iptables): a rule that assigns a traffic class now generates the CLASSIFY target with the class it names. The rule was generated without a target, so it counted packets and classified nothing, and traffic shaping downstream never saw the class.
* Compiler (iptables): a rule that matches TCP flags (or an IP header option) and additionally carries a rate limit or a time restriction now loads. The two matches were written without a space between them (`--tcp-flags ALL SYN-m limit ...`), which iptables rejected as an unknown TCP flag, so the rule was missing from the running firewall.
* Compiler (iptables): a rule that names an interface and applies in both directions no longer produces a rule the packet filter refuses. Once such a rule is placed in the postrouting or prerouting chain, only one of the two directions can still be matched there; the compiler generated both and iptables rejected the impossible one with "Can't use --in-interface with POSTROUTING", which stopped the activation script at that point.
* Compiler (iptables): a rule that rejects with a TCP reset now loads when the compiler has to move its action into a helper chain, which it does for logged rules, for rules with a negated source, destination or service, and for rules the optimizer splits. The reject rule lost the `-p tcp` match in the process, and iptables rejects `--reject-with tcp-reset` without it, so the rule was missing from the running firewall and the traffic fell through to the policy below. For a negated service the rule is now split, so TCP is reset and every other protocol gets the configured ICMP unreachable. nftables was not affected, it keeps the protocol match inline.
* Compiler (iptables): a rule that uses a custom service now carries the protocol the service is defined for, so a service whose code needs a preceding protocol match (`-m tcp --tcp-flags ...` for example) produces a rule that loads instead of being rejected with "TCP match requires '-p tcp'".
* Compiler (iptables): ip6tables NAT rules that match a specific ICMPv6 type now produce a valid rule. The rule used the IPv4-only `--icmp-type` option; it now uses `-m icmp6 --icmpv6-type`, matching the policy compiler.
* Compiler (iptables): the generated script waits at most five seconds for the iptables lock (`-w 5`) instead of waiting indefinitely (`-w`). A plain `-w` blocks forever while another process holds the lock, which stalls an unattended rollout with no error; the script now aborts with iptables' "Stopped waiting" message instead. Firewalls pinned to an iptables older than 1.6.0, which cannot express a timeout, keep the plain `-w`.
* Compiler (iptables, nftables): a dual-stack firewall whose rules mix IPv4 and IPv6 addresses no longer aborts compilation. The shadowing detector compared an IPv4 address directly against an IPv6 one, which raised an error and stopped the whole firewall from compiling; the two families are now correctly treated as non-overlapping.
* Compiler (iptables, nftables): a dual-stack interface or host used in a rule now renders its IPv4 address in the IPv4 ruleset and its IPv6 address in the IPv6 ruleset, instead of always using its first address. A single-stack interface or host used in the wrong address family (for example an IPv6-only tunnel in the IPv4 ruleset, or an IPv4-only host in the IPv6 ruleset) is now dropped from that ruleset instead of emitting a mismatched-family match the packet filter refuses to load.
* Compiler (iptables, nftables): a firewall that limits how many log messages its rules may produce now gets that limit into the generated ruleset. The setting was read nowhere, so a logging firewall under load or under attack wrote log lines at full rate and could fill its disk. On nftables a logged rule is now split into a rate-limited log rule and the rule carrying the action, matching what iptables generates; the limit throttles the log message, not the traffic.
* Compiler (iptables, nftables): a NAT rule whose translated service has a different protocol than its original service is now reported as an error, matching Firewall Builder. Such a rule was silently compiled into a translation that does not do what the rule says.
* Compiler (iptables, nftables): a source translation to an unnumbered interface is now reported as an error, matching Firewall Builder. Such an interface never carries an address, so there is nothing to translate the source to; iptables got a `-j SNAT` with no address behind it and refused it, which stopped the activation script, and nftables silently masqueraded instead, translating the traffic to the address of whatever interface it left by.
* Compiler (iptables, nftables): a REDIRECT (or port-translating DNAT/SNAT) rule whose only match is on the connection owner, such as a transparent-proxy rule that redirects a user's traffic to a local port, now carries the transport protocol it needs. The protocol is taken from the redirect target port, so the rule loads instead of being rejected for a port mapping without a preceding protocol match.
* Compiler (iptables, nftables): a rule or NAT rule that matches a MAC address now generates a loadable rule. The MAC was emitted as if it were an IP address (`-s 00:10:4b:...` / `ip saddr 00:10:4b:...`), which the packet filter rejects; it now uses the MAC match (`-m mac --mac-source` for iptables, `ether saddr`/`ether daddr` for nftables). A MAC used as a destination is reported as an error on iptables, which can only match the source MAC.
* Compiler (iptables, nftables): a rule or NAT rule that matches a Tag Service now matches the packet mark it names. The mark match was dropped from the generated rule, so a rule meant to match only marked packets matched every packet instead, which lets traffic through a rule that was supposed to be selective.
* Compiler (iptables, nftables): a rule that matches an interface in a chain that never sees it is now reported as an error and left out of the generated ruleset. A packet has no incoming interface in the postrouting and output chains and no outgoing one in the prerouting and input chains, so a rule such as "classify inbound traffic on eth0", which has to go into postrouting, can never match. iptables refused it with "Can't use --in-interface with POSTROUTING" and the activation script stopped there, leaving the firewall half-loaded; nftables accepted the rule and silently matched nothing.
* Compiler (iptables, nftables): a rule that rejects with a TCP reset and matches a custom TCP service is no longer downgraded to an ICMP unreachable with a spurious "can be used only with TCP services" warning. The compiler did not recognise the protocol of a custom service.
* Compiler (iptables, nftables): a rule that tags packets now sets the mark. On iptables the rule was generated without a target, so it counted packets and marked nothing, and the companion rule that saves the mark to the connection was rejected by iptables as "CONNMARK target: No operation specified", which stopped the script at that point.
* Compiler (iptables, nftables): a rule with a custom action now runs the target it names (for example `-j TCPMSS --clamp-mss-to-pmtu`). The target was left out of the generated rule, so the rule counted packets and did nothing else. nftables cannot run an iptables target and now reports such a rule instead of generating a rule that does nothing.
* Compiler (iptables, nftables): an IP service with an unknown DiffServ class name (for example "AF4", which is missing its drop-precedence digit) now reports a clear error instead of emitting a rule the packet filter refuses to load. Valid DiffServ classes (af41, cs0, be, ef, ...) and numeric code points are unaffected.
* Compiler (iptables, nftables): an IPv4 address range used in an IPv6 rule (or an IPv6 range in an IPv4 rule) is now dropped from that address family instead of being emitted. Address ranges slipped through the address-family filter, so a rule meant for IPv4 produced an IPv6 ruleset that the packet filter refused to load.
* Compiler (iptables, nftables): IPv6 SNAT and DNAT rules that also translate the port now bracket the address (for example `[fec0::1]:80`), so the generated ruleset loads. Without the brackets the port was read as part of the IPv6 address.
* Compiler (nftables): a firewall that logs via netlink (NFLOG) and has one of the "Log IP options", "Log TCP options" or "Log TCP sequence numbers" settings enabled now produces a ruleset that loads. nftables refuses a log statement that combines a netlink group with those flags, so the whole firewall failed to activate. The flags are now left out with a warning, matching the iptables NFLOG target, which has no counterpart for them either.
* Compiler (nftables): a firewall with no explicit policy rules but with automatic rules enabled (accept established/related, drop invalid, drop non-SYN TCP) now installs its filter table with the default-drop policy and those rules, matching the iptables output. Previously it produced an empty ruleset that filtered nothing, leaving the host effectively open.
* Compiler (nftables): a NAT rule that translates the source to an interface whose address is only known at run time (a PPP or DHCP interface) now masquerades, as the iptables output does. The compiler took the address of some other interface of the firewall instead, so the traffic left with a source address that does not belong to the link it went out on and the answers never came back. Where the address cannot be determined at all, the rule is now reported and left out instead of silently masquerading, which would translate the traffic to a different address than the rule asks for.
* Compiler (nftables): a NAT rule that translates only the port now performs the translation instead of letting the traffic pass untranslated. A redirect to a local port, a destination-port-only DNAT and a source-port-only SNAT were all compiled into a plain `accept` in the postrouting chain, with a "no chain assignment for NAT rule type" error. Combined source and destination translation (SDNAT) that also translates a port now works as well; it previously either errored out or translated the address only.
* Compiler (nftables): a NAT rule whose original source or destination address is negated now produces a ruleset that loads. The generated rule used an invalid negation (`ip saddr ! ...`) that nftables rejected; it now uses the correct `ip saddr != ...` form.
* Compiler (nftables): a NAT rule whose original source or destination negates a group of addresses now matches none of them, as the rule says. The group was split into one rule per address, each excluding a single address, so every address of the group still matched one of the rules and got translated.
* Compiler (nftables): a NAT rule that translates a whole network (the iptables NETMAP target) now maps the addresses one to one, so 10.141.11.4 becomes 192.168.2.4 as it does on iptables. The generated rule handed nftables a plain address range instead, and the kernel then picked an arbitrary address out of the target network for every connection, which breaks any setup that relies on a fixed mapping.
* Compiler (nftables): a firewall that logs invalid packets now logs them at the debug level and, when netlink logging is enabled, sends them to the configured NFLOG group. nftables defaults a log statement without a level to "warning", so those messages reached the console and the default syslog targets on a firewall under a packet flood. The iptables output has always used debug for this rule.
* Compiler (nftables): a firewall that drops TCP sessions opened before the firewall restart no longer drops legitimate new connections along with them. The rule compared the whole TCP flags byte against SYN, so a connection that negotiates ECN (a SYN packet with the ECE and CWR bits set, which Linux sends when `tcp_ecn` is on) was dropped. It now inspects only the SYN, RST and ACK bits, the same match the iptables output uses.
* Compiler (nftables): a long log prefix is no longer cut in half. The compiler shortened it to 63 characters, while nftables takes 127, so a descriptive prefix or one whose macros expand to a long string (a long rule-set name behind %R, for example) lost its tail and log parsers keyed on the full prefix stopped matching.
* Compiler (nftables): a rule with the Accounting action now counts the traffic it matches, in a named counter that `nft list counters` reads back. An accounting name nftables cannot use for a counter, one containing a space for example, is reported as an error instead of producing a ruleset that fails to load. The rule was generated without any statement at all, so it counted nothing and the traffic accounting an admin set it up for stayed empty. iptables counts the same traffic in a chain of its own.
* Compiler (nftables): a rule with the Pipe action now hands the packet to userspace instead of aborting with "Pipe action not yet supported by nftables compiler". The rule was generated without a verdict, so the traffic an intrusion-detection or userspace-filtering setup was supposed to inspect fell through to the rule below.
* Compiler (nftables): a rule that tags packets and saves the mark to its connection now does both. The connection mark was dropped, so the mark was lost as soon as the connection was established and every later packet of it went unmarked. The rule now saves the mark and the prerouting and output chains restore it, the same pair the iptables output generates.
* Compiler (nftables): a rule that tags packets or assigns a traffic class now does so, instead of aborting with "not yet supported by nftables compiler". Such rules go into a mangle table of their own, whose chains run before the routing decision, so a mark is available to policy routing and to traffic shaping exactly as it is on iptables. ([#122](https://github.com/Linuxfabrik/firewallfabrik/issues/122))
* Compiler (nftables): a rule or NAT rule that negates its service now matches the opposite of that service instead of the service itself. The negation was honoured for TCP and UDP port matches only; for an ICMP service, an IP service, and for a service matched on both TCP and UDP, it was silently dropped, so the rule did exactly the opposite of what it says. A negated custom service, which nftables cannot invert, is now reported as an error.
* Compiler (nftables): a rule that lists several services of the same protocol, for example a set of ICMP types or several IP or custom services, now generates a rule for every one of them. Only the first service was rendered and the rest were silently dropped, so a rule such as "accept the useful ICMP types" ended up accepting only the first type. Only TCP and UDP services, which nftables can express as one destination port set, keep sharing a rule.
* Compiler (nftables): a rule that matches a Tag Service whose mark carries a mask (for example `0x1/0xff`) now produces a ruleset that loads. nftables read the slash as a prefix length and refused the rule; the mask is now applied with a bitwise match, the same translation `iptables-translate` performs.
* Compiler (nftables): a rule that uses a loopback interface which has no IP address now aborts compilation with a clear error instead of silently dropping the rule, matching the iptables compiler.
* Compiler (nftables): a rule that uses an IP service with protocol number 0 ("any protocol" in Firewall Builder) no longer restricts the rule to IP protocol 0. The generated `meta l4proto 0` matched only packets whose protocol field is literally 0, so such a rule matched nothing at all; iptables reads protocol 0 as the "all" wildcard. The protocol match is now left out, which is what "any protocol" means.
* Compiler (nftables): a rule with a negated interface now matches every other interface, as the rule says. The negation was dropped, so an anti-spoofing rule such as "drop packets with a loopback source that do not arrive on the loopback interface" did the exact opposite: it dropped the legitimate loopback traffic and let the spoofed packets through. Rules that differed only in the negated interface were also collapsed into one.
* Compiler (nftables): a rule whose time restriction runs past midnight (22:00 to 06:00, for example) now matches that night. nftables has no notion of a window that wraps, so the generated rule asked for a time both later than 22:00 and earlier than 06:00 and matched nothing at all, silently disabling every such rule. iptables has always matched these windows correctly.
* Compiler (nftables): an IP service that matches fragmented packets now generates a rule that actually matches fragments. The fragment condition was silently dropped, so a rule meant to block fragments matched on the protocol alone and let fragments through (or, for an "any" protocol, matched nothing at all).
* Compiler (nftables): an IP service that matches IP options (source routing, record route, router alert) now generates a rule that carries the option match, instead of dropping the condition and matching every packet of that protocol. An option nftables cannot match, the timestamp option, is now reported as an error.
* Compiler (nftables): an IPv6 network object with a /0 netmask (equivalent to "any") is now reported as a likely configuration error, matching the iptables compiler which already caught the IPv4 case.
* Compiler (nftables): firewall rules with a negated source that are directed outbound to a firewall address are no longer silently dropped. The nftables compiler now keeps them, matching the iptables compiler.
* Compiler (nftables): generated rules now carry a counter, so `nft list ruleset` shows per-rule packet and byte hit counts, matching the implicit counters of the iptables output.
* Compiler (nftables): IP service objects that match on a DSCP value now generate a rule that loads. nftables requires lowercase DiffServ class names (for example "af11" instead of "AF11") and the IPv6 header in IPv6 policies. A match on the legacy ToS byte, which nftables cannot express, now reports a clear error instead of an unloadable ruleset.
* Compiler (nftables): IPv6 NAT rules are now written to a separate IPv6 NAT table instead of the IPv4 one. A firewall that used IPv6 NAT previously produced a ruleset nftables refused to load, because it placed IPv6 matches in an IPv4 table.
* Compiler (nftables): log rules of a firewall that logs via netlink (NFLOG) now honour the "Copy range" and "Queue threshold" settings, matching the iptables compiler. Both were silently ignored on nftables, so the logging daemon received full packet copies and no batching even where the firewall asked for the opposite.
* Compiler (nftables): log rules that use the "error" or "warning" severity level now produce a ruleset that loads. nftables only accepts the abbreviated level names, so the generated script previously emitted names it rejected.
* Compiler (nftables): NAT rules now emit the "random" and "persistent" flags when those options are set, matching the iptables compiler. Previously the flags were silently dropped on nftables.
* Compiler (nftables): on bridging firewalls, rules whose destination is a broadcast, multicast, or on-link network address are now placed in the forward chain like the iptables compiler, instead of also generating a spurious input-chain rule.
* Compiler (nftables): rule shadowing detection no longer reports false "Rule X shadows Rule Y below it" warnings when a rule negates its source or destination. The nftables compiler now runs the same shadowing detection as the iptables compiler, so both platforms report identical shadowing for the same firewall ([#136](https://github.com/Linuxfabrik/firewallfabrik/issues/136)).
* Compiler (nftables): rules and NAT rules that match an ICMPv6 service with no specific type now produce a ruleset that loads. The generated rule used `meta l4proto icmpv6`, a protocol name nftables does not recognise; it now uses `ipv6-icmp`.
* Compiler (nftables): rules that are restricted to a time of day now match at the same hours as the iptables output. nftables reads a written-out time such as "09:00" in the timezone of the host loading the ruleset, while iptables reads it as UTC unless the "use kernel timezone" setting is on, so on a host that is not on UTC the two platforms fired hours apart. The setting is now honoured on nftables as well; with it off the time is emitted in UTC. Note that the weekday of a time-based rule is always matched in UTC, which nftables cannot change; a rule that restricts both the weekday and the time now says so with a warning.
* Compiler (nftables): rules that carry a rate limit now emit it as a native `limit rate` match, matching the iptables compiler. Previously the limit was silently dropped on nftables, so a rule meant to be rate-limited passed all traffic.
* Compiler (nftables): rules that match a DNS name beginning with a digit (for example `6bone.net`) now produce a ruleset that loads. nftables read the bare name as a number and rejected the rule; the name is now quoted so nftables resolves it as a hostname.
* Compiler (nftables): rules that match a single TCP flag (for example SYN-only, `--tcp-flags SYN SYN`) now produce a ruleset that loads. The generated `tcp flags syn / syn` form is rejected by current nftables when the mask is a single flag; the compiler now emits the equivalent bitwise match.
* Compiler (nftables): rules that match on TCP flags (for example SYN-only or non-SYN packets) now generate the correct flag match instead of matching all TCP traffic, matching the iptables compiler.
* Compiler (nftables): the logging rate limit can be set again in the nftables firewall settings. Both fields were greyed out as unsupported although the compiler emits the limit.
* GUI: the firewall settings offer the same "Default action on Reject" choices as the per-rule action editor and as Firewall Builder: "ICMP admin prohibited" and "ICMP protocol unreachable" were missing, so a firewall imported with one of them could not keep it. The list also offered a plain "ICMP unreachable" that no compiler maps to a defined ICMP type.
* Installing the GUI variant (`firewallfabrik[gui]`) no longer fails to resolve its Qt dependency.


## [v1.9.0] - 2026-07-12

### Added

* CLI: `fwf-upgrade` writes a `.fwf` file in the current format without opening the GUI. It converts a Firewall Builder `.fwb` file and upgrades an older `.fwf` file to the current schema. Given a directory, it scans recursively and processes every `.fwf` and `.fwb` below it, which allows batch-upgrading many files at once. A `--dry-run` option lists which files would be upgraded or converted without writing anything. Output is deterministic, so processing the same file repeatedly produces identical results, which suits scripting and rewriting a git history of `.fwb` files ([#132](https://github.com/Linuxfabrik/firewallfabrik/issues/132)).


## [v1.8.1] - 2026-07-01

### Fixed

* GUI: FirewallFabrik no longer crashes when the object tree is rebuilt while a search is open.


## [v1.8.0] - 2026-06-29

### Added

* Compiler (iptables, nftables): the "Accept ICMP redirects" and "Accept source-routed packets" hardening settings are now also applied to the IPv6 stack on firewalls that handle IPv6, not just IPv4.
* Compiler (nftables): the kernel-hardening and conntrack tuning options from the firewall's Host OS settings (reverse-path filtering, SYN cookies, ICMP broadcast handling, conntrack table size and similar) are now applied by the generated script. These are backend-independent `/proc/sys` settings that were previously only honoured by the iptables compiler. The matching fields are now editable for nftables firewalls.
* Documentation: the user guide now explains the `.fwf` YAML file structure and includes a mapping from every firewall setting in the GUI to its YAML key, so the file can be edited safely for bulk changes and automation.

### Deprecated

* Host OS setting "TCP fack": FACK loss detection was removed from the Linux kernel (replaced by RACK), and the `/proc/sys/net/ipv4/tcp_fack` knob is a no-op on all supported kernels (RHEL 8/9/10, Fedora). The option is greyed out in the GUI and is no longer written to the generated script.

### Fixed

* Compiler (iptables): the conntrack tuning options (maximum connections, hash table size, liberal TCP tracking) were silently ignored and are now written to the kernel as configured.
* Compiler (nftables): switching a firewall from iptables to nftables now removes leftover legacy iptables rules when the policy is activated. Previously the old rules could remain in the kernel and shadow the new nftables rules, so a changed rule appeared to have no effect even after a reboot.
* Compiler (nftables): the IPv4/IPv6 forwarding commands are now indented consistently in the generated script.
* Compiler (nftables): the backup SSH access rule of the "block" panic action is now generated as intended. It was tied to the wrong setting and never appeared, which could lock an administrator out when blocking a firewall.
* Documentation: corrected user-guide statements that no longer matched the application, for example bridges are configured with iproute2 instead of brctl, address ranges support IPv6, the firewall "stop" action resets the built-in chains to ACCEPT, and several dialog, button and menu labels.
* GUI: the "Update Standard Library" preview now lists the affected firewalls and rules under each object when a row is expanded. Previously those rows appeared blank because their content was placed in columns that were pushed off-screen.


## [v1.7.0] - 2026-06-18

### Added

* Object tree context menu: "Collapse", "Collapse All", "Expand" and "Expand All" entries. The plain variants toggle the clicked node only; the "All" variants recurse over every descendant.

### Changed

* User guide: expanded the nftables introduction with background from the Linux 3.13 release notes (kernel/userspace split, unified syntax, atomic updates, first-class sets, backwards compatibility via iptables-nft).
* User guide: revised the "Migrating from Firewall Builder" chapter. Platform compatibility tables now show explicit version coverage (verified against the fwbuilder source), clearer columns ("Supported by FwBuilder", "Today (2026)", "Why dropped/deferred"), and a corrected categorisation (HP ProCurve moved to discontinued; ipfilter and ipfw moved to deferred). Cluster support caveat added.
* User guide: update Linux desktop integration instructions so that icons in `$HOME/.local/share/icons/hicolor` can be updated without custom theme index file.

### Fixed

* GUI: editing a standalone IPv4 or IPv6 address object no longer shows a Netmask field. A standalone address always matches a single host, so its netmask never affected the generated firewall and only produced confusing, inconsistent values. The field still appears when editing an interface address, where the netmask is relevant.
* GUI: selecting a predefined Any object (network, service or time interval) in the object tree now shows a short explanation of what Any matches in a rule, instead of an editable form with meaningless values such as address 0.0.0.0.


## [v1.6.0] - 2026-05-07

### Added

* Compiler (iptables): now honours the "Use kernel timezone" firewall option on time-based rules. When enabled, `--kerneltz` is appended to the `-m time` match so timestamps are interpreted in the kernel timezone instead of UTC. Nftables matching (`meta hour`, `meta day`) already always uses the kernel timezone, so the option has no nftables equivalent.
* Compiler (iptables, nftables): now honours the "Log IP options", "Log TCP options" and "Log TCP sequence numbers" firewall options on logging rules. Iptables emits the corresponding LOG target flags (`--log-ip-options`, `--log-tcp-options`, `--log-tcp-sequence`), nftables the equivalent `log flags ip options` / `log flags tcp options` / `log flags tcp sequence` clauses. Per-rule settings override the firewall-level default.

### Changed

* GUI: File > Open Recent shows distinguishing path segments per entry, full path stays in the tooltip.

### Fixed

* Iptables and nftables firewall settings dialogs: corrected checkboxes that were shown as unsupported even though the compiler honoured them. Affected options included "Drop new TCP sessions without SYN", "Log all rules", "Use numeric log levels", "Bridging firewall" and "Clamp MSS to MTU".
* Iptables and nftables firewall settings dialogs: greyed-out checkboxes now show a tooltip that explains *why* the option is disabled (not yet implemented, not applicable to the platform, or replaced by automatic behaviour) instead of just repeating the label.
* Nftables firewall settings dialog: greyed out the checkboxes for options that the nftables compiler does not implement (e.g. "Use iptables-restore", "Use ipset module", "Logging rate limit"). Previously these checkboxes accepted clicks but had no effect.


## [v1.5.1] - 2026-05-07

### Fixed

* GUI: Opening the Platform Settings dialog of an nftables firewall no longer crashes with `KeyError: 'ulog_cprange'`. The nftables schema (`platforms/nftables/defaults.yaml`) was missing the `ulog_cprange` and `ulog_qthreshold` entries that the dialog reads at populate time; both are now declared with `supported: false`.

### Security

* **ci**: Scope `GITHUB_TOKEN` permissions in the dependabot-auto-merge workflow to the job level, with top-level now `read-all`. Matches the pattern used by the other Linuxfabrik workflows and addresses the OpenSSF Scorecard `Token-Permissions` finding.


## [v1.5.0] - 2026-04-29

### Added

* File > Reload now has the keyboard shortcut Ctrl+R
* Install options dialog: add "Password or passphrase" field and "Remember passwords" checkbox. Users with passphrase-protected SSH keys or password-based authentication can now enter their credentials directly in the dialog before installation. Passwords are cached in memory for the session duration (never stored on disk) when "Remember passwords" is enabled in Preferences. The installer automatically detects SSH/SCP/sudo password prompts and responds with the entered password ([#72](https://github.com/Linuxfabrik/firewallfabrik/issues/72))
* Object tree: NAT / Policy / Routing rule-set nodes show their rule count (e.g. "60 rules") in the Attribute column, so an admin can size a rule set at a glance without opening it. The count updates live as rules are added, deleted or pasted
* Renaming a firewall, host, or interface that has child objects (IP addresses, MAC addresses, sub-interfaces) now shows a warning dialog offering to auto-rename the children using the standard `host:interface:ip` / `host:interface:mac` naming scheme (matching fwbuilder behaviour)

### Changed

* AddressRange objects that happen to cover an exact CIDR block are now compiled to the short CIDR form (`-s 192.168.4.0/24` for iptables, `ip saddr 192.168.4.0/24` for nftables) instead of the verbose range form. The `xt_iprange` kernel module is therefore only loaded when actually needed. Single-host AddressRanges are emitted as a bare address in nftables. Non-CIDR ranges keep the existing range form
* Dynamic Groups: the criteria rows are now combined with logical AND by default, instead of OR. A dynamic group named "monitoring vms (prod03)" with criteria `Firewall + monitoring` and `Firewall + prod03` therefore now contains only firewalls that carry both tags, not the union of all monitoring firewalls and all prod03 firewalls. This closes a class of overly permissive firewall rules where a multi-criterion group used as source/destination unintentionally widened the rule. A new "Match: AND / OR" selector in the Dynamic Group editor lets you switch back to the previous OR semantics per group when a cross-type union (e.g. `Hosts tagged production` + `Networks tagged production`) is actually wanted. Groups imported from a Firewall Builder `.fwb` file are explicitly marked as OR, so existing imports keep their original behaviour ([#82](https://github.com/Linuxfabrik/firewallfabrik/issues/82))
* Interface context menu no longer offers "New Attached Networks" or "New Failover Group". Both items led to broken objects that ended up at the top level of the library instead of as a child of the interface, because the underlying data model has no link between Group objects and an interface. The menu items will return once the cluster pipeline is fully ported ([#78](https://github.com/Linuxfabrik/firewallfabrik/issues/78), [#84](https://github.com/Linuxfabrik/firewallfabrik/issues/84), [#85](https://github.com/Linuxfabrik/firewallfabrik/issues/85))
* Policy and NAT action context menus no longer offer the "Branch" entry. The branch-action editor's drop area is not wired to save the branch target, and no compiler resolves the target ruleset, so creating a branch rule produced silent data loss and an undefined compile result. The entry will return once the full branch-action pipeline is ported ([#83](https://github.com/Linuxfabrik/firewallfabrik/issues/83), [#90](https://github.com/Linuxfabrik/firewallfabrik/issues/90))
* iptables and nftables firewall settings: the Compiler tab now lists "Table name", "Compiler", "Compiler command line options", "Output file name" and "Script name on the firewall" in a single aligned grid, all input fields line up and render with normal (non-disabled) text. Two inline hint paragraphs were dropped and their content merged into the tooltips of the affected fields
* iptables, nftables and Linux settings dialogs: empty text fields no longer show the schema default as greyed-out placeholder text. The placeholder fell back to the default value when no explicit placeholder was configured, which made empty fields like "Output file name" or "Script name on the firewall" look pre-filled and disabled. Only schema entries with an explicit `placeholder` key (e.g. "Table name", Linux binary paths like `/sbin/iptables`) still show hint text

### Fixed

* Clipboard shortcuts (Ctrl+C, Ctrl+X, Ctrl+V) now work reliably for tree objects. Previously, clicking any widget outside the object tree (e.g. a combo box or checkbox in the editor panel) silently rerouted clipboard operations to the policy view, causing copy/paste on tree objects to do nothing. Focus is now only set to "policy view" when the focused widget lives inside the MDI area; other panels (editor dock, toolbar) keep the previous routing target
* Compiler (iptables) now emits `--icmp-type any` on rules whose service matches "any ICMP type" and the explicit `-m icmp6` match module on rules whose service specifies a concrete ICMPv6 type, matching the fwbuilder output format. For an "any ICMP6" service fwbuilder only writes `-p ipv6-icmp`; fwf now follows the same asymmetry. Previously the compiler emitted the bare `-p icmp` / `-p ipv6-icmp` protocol match, which works on modern kernels but diverges from fwbuilder output and fails on older ip6tables where the icmp6 match module must be loaded explicitly
* Compiler (iptables) now emits `-i +` / `-o +` wildcard interface matches on mangle-table PREROUTING and POSTROUTING rules when the user rule has direction Inbound or Outbound but no specific interface, matching fwbuilder. Previously only the FORWARD chain got the wildcard, so mangle multicast/broadcast drop rules landed without an explicit direction marker in the generated script
* Compiler (iptables) now honours the firewall-level option `use_numeric_log_levels` on LOG rules: when enabled it emits numeric syslog levels (e.g. `--log-level 5`), when disabled it emits the symbolic name (e.g. `--log-level notice`). Previously fwf always emitted the symbolic form, which differed from fwbuilder output for firewalls that had the numeric option set. Both forms are functionally identical; the numeric form is what every iptables version understands out of the box
* Compiler (iptables) now emits the automatic TCPMSS clamping rule on the FORWARD chain of the mangle table (matching fwbuilder) instead of the POSTROUTING chain. The rule is skipped when IP forwarding is disabled for the active address family (`linux24_ip_forward` / `linux24_ipv6_forward`), and on IPv6 it is skipped for ip6tables < 1.3.8 because the TCPMSS target is unavailable there
* Compiler (iptables) now expands a firewall object used in a rule's source or destination to one rule per non-loopback interface address, matching fwbuilder. Anti-spoofing rules with the firewall itself as source therefore now generate one drop rule per own IP, not just one for the address of the rule's own interface. Previously the other own IPs were silently missed, so a spoofed packet from another own interface address would not have been blocked
* Compiler (iptables) in `iptables-restore` mode now emits each rule as `echo "-A CHAIN ..."` (matching fwbuilder), instead of a bare ` CHAIN ...` line without `echo` and without `-A`. Previously the heredoc piped to `iptables-restore` was missing both the `echo` wrapper and the required `-A` append marker on every rule, so `iptables-restore` rejected the script and either applied no rules at all or fell back to overly permissive defaults. The rule label and chain-create lines (`echo "# Rule X"`, `echo ":chain - [0:0]"`) now also end with a newline so each statement appears on its own line. Affects only firewalls with `use_iptables_restore` enabled. Nftables is not affected because its body is always loaded via `nft -f /dev/stdin` ([#77](https://github.com/Linuxfabrik/firewallfabrik/issues/77))
* Compiler (iptables) TCPMSS clamping rule now includes the `-m tcp` match module (`-p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS ...`), matching fwbuilder output. Functionally equivalent on modern iptables where the tcp match is auto-loaded, but consistent with what fwbuilder emits
* Compiler (iptables) no longer writes `echo 0 > /proc/sys/net/ipv4/tcp_fin_timeout` or `echo 0 > /proc/sys/net/ipv4/tcp_keepalive_intvl` into the generated script when the firewall option is left at its default ("kernel default"). Firewall Builder represented "not set" for these two options as the integer `0`; fwf was honouring that literal `0` and pushing it into the kernel, which would have closed TIME_WAIT sockets instantly and disabled TCP keepalive probe spacing. Both values are now skipped exactly as fwbuilder itself skips them
* Compiler (iptables) temporary chain names are now stable across repeated compilations. Recompiling an unchanged policy produces byte-identical iptables scripts, so CI/CD pipelines, checksums and `diff` / `git diff` no longer see phantom changes. Compiling the same policy from a `.fwb` source and from its saved `.fwf` counterpart also produces byte-identical output
* Compiler (iptables, nftables) now aborts compilation with a clear error when a regular firewall interface has IP address 0.0.0.0 / :: or netmask /0, matching fwbuilder. Such interfaces are configuration mistakes and previously slipped through the compile, producing dead `-s 0.0.0.0` rules in the generated script instead of a visible error. Dynamic, unnumbered and bridge-port interfaces are unaffected because they only get their address at runtime
* Compiler (iptables, nftables) now honours the "Address family" attribute of Custom Services imported from Firewall Builder `.fwb` files: a CustomService marked as IPv4-only is dropped from rules during the IPv6 compile pass (and vice versa), matching fwbuilder. Rules that end up with no service left are dropped instead of producing a misleading "Custom service ... is not configured for ..." error followed by an unmatched `log drop`. Previously the address-family attribute was ignored on import and CustomServices appeared in both compile passes
* Compiler (iptables, nftables) now respects the "Assume firewall is part of 'any'" option (`firewall_is_part_of_any_and_networks`) when deciding whether to split rules whose source or destination is a Network object that contains one of the firewall's own interface addresses. With the option disabled (fwbuilder default), such rules no longer produce an extra INPUT clone for FORWARD-direction rules with a matching destination network or an extra OUTPUT clone for FORWARD-direction rules with a matching source network. `no_input_chain` / `no_output_chain` rule options and the `bridging_fw` firewall option now also suppress the respective clone. Previously the split always fired, leading to INPUT / OUTPUT rules that fwbuilder would not have emitted
* Compiler (nftables) now emits an automatic TCPMSS clamping rule at the top of the forward chain when the "Clamp MSS to path MTU" firewall option is set, matching the iptables compiler. The rule is skipped when IP forwarding is disabled for the active address family
* Compiler (nftables) now drops policy rules whose interface has no IPv4 / IPv6 addresses matching the active address family, matching fwbuilder and the iptables compiler. Rules on dynamic, unnumbered and bridge-port interfaces are kept because those interfaces acquire their addresses at runtime
* Compiler (nftables) now warns and falls back to the configured reject action when a Reject rule with "TCP RST" references non-TCP services, and splits rules that mix TCP with non-TCP services so only the TCP subset emits `reject with tcp reset`. Previously the non-TCP rules silently emitted `reject with tcp reset`, which the kernel accepts but never matches
* Compiler (nftables) now splits Reject rules whose service is "any" into a TCP-only clone that uses `reject with tcp reset` and a fall-through clone that uses the configured reject action, matching fwbuilder and the iptables compiler. Previously the `reject with tcp reset` part was missing
* Compiler (nftables) now warns about and drops policy rules that use a UserService (`meta skuid`) outside the OUTPUT chain, matching the iptables compiler. Previously those rules were silently emitted into INPUT/FORWARD, where `meta skuid` has no effect
* Compiler now routes Inbound policy rules whose destination is a broadcast (255.255.255.255) or multicast address (224.0.0.0/4, ff00::/8) into the INPUT chain instead of FORWARD, matching fwbuilder semantics. The same applies to Outbound rules whose source is a broadcast or multicast address: they now go into OUTPUT. AddressRange objects that cover only broadcast or multicast addresses are treated the same way. Applies to both iptables and nftables compilers
* Compiler now emits IPv4 rules for single-address AddressRange objects that contain an IPv4 address and IPv6 rules for those that contain an IPv6 address. Previously all single-address AddressRanges were forced into the IPv6 output, which silently dropped IPv4 rules using start=end AddressRange shortcuts. Applies to both iptables and nftables compilers
* Compiling a firewall whose outbound rules target an AddressRange object (e.g. a custom-defined subnet) no longer aborts the iptables compiler with an internal error
* Compiler no longer repeats the same "Rule X shadows Rule Y below it" warning once per expanded variant of the rule (one message per firewall, address family and interface combination). Each logical shadow is now reported at most once per compilation
* Compiler no longer reports spurious "Rule X shadows Rule Y below it" warnings for rules whose source or destination is "any" (matching fwbuilder). Affects both iptables and nftables compilers
* Compiler now emits the correct chains for rules that use an AddressRange object (e.g. a subnet defined via start/end pair rather than as a Network): NAT MASQUERADE rules keep their `-s <subnet>` source filter, outbound rules whose source overlaps a firewall interface are placed in FORWARD in addition to INPUT/OUTPUT, and policy rules whose destination includes both the firewall and an AddressRange emit the expected `-A OUTPUT -d <subnet>` line. Previously these cases produced overly permissive MASQUERADE, missing FORWARD entries, and missing AddressRange-destination entries. The same AddressRange-aware chain decisions now apply to the nftables compiler as well
* Compiler no longer emits the informational "Adding of virtual address for address range is not implemented" warning for every AddressRange used as a NAT target. The generated iptables rules are unchanged; only the noisy message is gone
* Recent files menu: entries pointing to files that no longer exist (moved, deleted, removable media unmounted) are dropped from the menu at startup so clicking them no longer fails with "file not found"
* REJECT rules for IPv6 policies now emit the correct `icmp6-*` reject types (`icmp6-port-unreachable`, `icmp6-addr-unreachable`, `icmp6-adm-prohibited`) instead of the IPv4 `icmp-*` names. The previous output was rejected by `ip6tables-restore` and the IPv6 script failed to load on the firewall. The nftables compiler now emits `reject with icmpv6 <type>` for IPv6 policies for the same reason, and additionally recognises "ICMP host/net prohibited" reject types that previously fell back to a generic `reject`
* NAT rules that use an AddressRange spanning multiple CIDR blocks (e.g. `195.222.0.0-255.255.0.0`) are now expanded into the set of minimum-size CIDR blocks that covers the range, matching the form `iptables -s <cidr>` accepts. Previously fwf emitted a single `-s <start>-<end>` token which is not valid `-s`/`-d` syntax
* Object tree: when a firewall, host or interface is renamed and the user accepts the auto-rename-children prompt, the tree now refreshes the renamed child IP and MAC address objects as well, not only the parent. Previously the tree kept showing the old child names (e.g. `oldfw:eth0:ip`) until the file was reloaded, even though the database already held the new names
* Policy rules whose source is an AddressRange overlapping a firewall interface no longer generate a redundant OUTPUT rule when the destination is the firewall itself (and vice versa). The kernel routes such self-traffic through `lo` and never into OUTPUT/INPUT, so the extra rule could never match; fwbuilder omits it too. Applies to both the iptables and the nftables compiler
* Drag & drop from the object tree: the drag pixmap is set from the item's tree icon, with a red count badge for multi-select. On X11 the icon follows the cursor during the drag; on Wayland compositors the drag pixmap is currently not rendered (Qt6 limitation on Wayland)
* File > Reload now works reliably for both native `.fwf` files and imported `.fwb` files: the policy view is refreshed from disk, the "modified" marker (`*`) is cleared from the title bar, and the confirmation prompt appears before unsaved changes are discarded. Previously Reload silently did nothing
* Generated firewall script now checks for the required tool (`iptables`, `ip6tables`, `nft`, …) before running every action (`stop`, `status`, `block`, `interfaces`, …), not only `start`. If the binary is missing the script aborts with a clear `"<tool>" not found` (iptables) or `Error: nft not found at <path>` (nftables) message and exits 1. Previously only `start` was guarded; the other actions silently failed at the first invocation of the missing binary and `status` even reported `"Firewall is not configured"` when in reality the tool was just absent. fwbuilder also only guarded `start`; this is an explicit improvement over the original behaviour
* Generated firewall script `stop` action now resets the built-in iptables / ip6tables INPUT, FORWARD and OUTPUT chain policies to ACCEPT after flushing the rule set (matching fwbuilder). Previously the policies stayed at DROP, so after `./fwf.sh stop` the firewall kept blocking all traffic and administrators had to run `iptables -P INPUT ACCEPT` etc. by hand to restore connectivity
* Copy/paste an interface onto another interface now creates a subinterface under the target (matching fwbuilder behaviour). The pasted interface's type is reset to "ethernet" and its management flag is cleared to prevent duplicates. Pasting an interface onto a firewall/host adds it as a top-level interface of that device
* Duplicating an address under an interface now places the copy in the canonical system group (e.g. User > Objects > Addresses for IPv4) instead of under the same interface, matching fwbuilder behaviour
* AddressRange objects in iptables policy rules now emit `-m iprange --src-range`/`--dst-range` matching. Previously, AddressRange destinations (e.g. 192.168.4.0-192.168.4.255) were silently dropped from compiled rules, making OUTPUT rules less restrictive than intended
* Compiler now emits platform-specific code for Custom Services (e.g. `-m conntrack --ctstate ESTABLISHED,RELATED`), Tag Services (`-m mark`) and User Services (`-m owner`) into compiled iptables and nftables rules. Previously this code was silently dropped, producing rules without any service matching - for example, an ESTABLISHED/RELATED rule became a bare `-j ACCEPT` that accepted all traffic instead of only established connections. Affects both policy and NAT compilers ([#72](https://github.com/Linuxfabrik/firewallfabrik/issues/72))
* Custom services with platform code defined for `iptables` or `nftables` are now correctly recognized by the compiler. Previously, using a custom service in a rule always aborted with "Custom service ... is not configured for the platform ..." even when the code was set ([#71](https://github.com/Linuxfabrik/firewallfabrik/issues/71))
* `fwf-ipt --all` and `fwf-nft --all` now skip firewalls flagged inactive in the database, matching fwbuilder. Previously every firewall on the matching platform was compiled regardless of the inactive flag. Naming an inactive firewall explicitly on the command line still compiles it. The "Found N firewall(s) to compile" line reports how many were skipped ([#89](https://github.com/Linuxfabrik/firewallfabrik/issues/89))
* Compile and Install dialogs now show a small firewall icon in the firewall name column of both the selection table and the progress sidebar. The icon is the same one used in the object tree, so the two views line up visually and the firewalls being processed are easier to scan
* Compile Firewalls: a compiler that crashed while writing its output file (e.g. permission denied on the destination path) is now reported as "compilation failed" and the process exits with a non-zero status. Previously such failures were silently reported as "compiled successfully"
* Install rules: when "Compiler > Output file name" contained a full path (e.g. `/home/user/fw/example.fw`) and "Installer > Directory on the firewall" was also set, the remote copy destination was built by concatenating both, producing a duplicated path such as `/home/user/fw//home/user/fw/example.fw` and aborting scp with exit code 1. The remote path is now always `<installer directory>/<filename>`, where the filename is taken from "Compiler > Script name on the firewall" if set and otherwise from the local output file. An absolute path in "Script name on the firewall" (e.g. `/opt/custom/myfw.fw`) is still honoured as-is. The tooltips now clearly separate the three fields: "Output file name" is the local filename of the compiled script on the workstation (e.g. `example.fw`), "Directory on the firewall" is the remote directory path on the firewall (e.g. `/etc/fw`), and "Script name on the firewall" is the remote filename inside that directory (e.g. `myfw.fw`) ([#72](https://github.com/Linuxfabrik/firewallfabrik/issues/72))
* Shadow detection no longer reports false "Rule X shadows Rule Y below it" warnings for TCP services that inspect TCP flags (e.g. `xmas scan`, `~Illegal Flags` groups). Such services were incorrectly treated as "any TCP" and appeared to cover every rule below them, which was especially visible on policies imported from Firewall Builder (`.fwb`) ([#73](https://github.com/Linuxfabrik/firewallfabrik/issues/73))

### Removed

* Dropped the legacy `use_ULOG` firewall option from the iptables and nftables schemas. The ULOG target was removed from modern Linux kernels years ago; `.fwb` files that still carry the flag are silently migrated to `LOG` at import time
* Nftables firewall settings no longer expose iptables-only options that the nftables compiler cannot act on: `add_mgmt_ssh_rule_when_stoped`, `configure_bonding_interfaces`, `configure_vlan_interfaces`, `ipv6_neighbor_discovery`, `limit_suffix`, `limit_value`, `load_modules`, `log_ip_opt`, `log_tcp_opt`, `log_tcp_seq`, `manage_virtual_addr`, `ulog_cprange`, `ulog_qthreshold`, `use_iptables_restore`, `use_kerneltz`, `use_m_set`, `use_numeric_log_levels`. They stay available under iptables, where fwbuilder also implements them

### Security

* Harden the Firewall Builder (`.fwb`) XML importer against malformed or malicious input files by switching to the `defusedxml` parser. Regular `.fwb` files continue to import unchanged


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

- Custom Service editor: Platform dropdown always reset to nftables instead of remembering the last selection ([#61](https://github.com/Linuxfabrik/firewallfabrik/issues/61)).
- Sporadic SIGSEGV crash when rebuilding the object tree after compilation or when closing/creating files ([#57](https://github.com/Linuxfabrik/firewallfabrik/issues/57)).


## [v1.4.2] - 2026-04-08

### Fixed

- Images not loading on the MkDocs documentation site due to broken relative paths in HTML image tags.
- Object tree attribute column too narrow on first use when "Show object attributes in the tree" is enabled ([#60](https://github.com/Linuxfabrik/firewallfabrik/issues/60)).


## [v1.4.1] - 2026-04-08

### Added

- Documentation on how to install Release Candidate (RC) versions
- MkDocs-based documentation site, deployed automatically to GitHub Pages

### Changed

- Update pre-commit hooks to latest versions
- Unify CONTRIBUTING with Linuxfabrik standards

### Fixed

- GUI failed to start on Wayland-only systems (e.g. GNOME without X11) because Qt defaulted to the xcb platform plugin ([#58](https://github.com/Linuxfabrik/firewallfabrik/issues/58)).
- Improved Wayland detection to also cover systems where only wayland-egl or wayland-brcm platform plugins are available ([#58](https://github.com/Linuxfabrik/firewallfabrik/issues/58)).
- `pyside6-rcc` not found when installed via `uv tool install` because the tool is inside the isolated virtual environment and not on the user's PATH ([#58](https://github.com/Linuxfabrik/firewallfabrik/issues/58)).
- Pre-compiled Qt resource file (`.rcc`) was written to the wrong directory during package build, causing unnecessary runtime recompilation.
- Sporadic SIGSEGV crash when opening a rule editor (action, comment, direction, metric, options) while another editor had unsaved changes ([#57](https://github.com/Linuxfabrik/firewallfabrik/issues/57)).


## [v1.4.0] - 2026-03-29

### Added

- "Flush entire ruleset" option for both iptables and nftables. When disabled, FirewallFabrik only manages its own tables/chains (e.g. `fwf_filter`, `fwf_nat` for nftables or `fwf_INPUT`, `fwf_FORWARD` for iptables), leaving rules created by other tools like Docker, CrowdSec and fail2ban untouched.

### Changed

- Default output file name changed from firewall object name to `fwf.sh`.
- Default script directory on the firewall changed from `/etc/fw` to `/etc`.
- Default table/chain prefix changed from `linuxfabrik` to `fwf`.

### Fixed

- Application no longer crashes with a segmentation fault when pressing Ctrl+C in the terminal.
- Coexistence mode: `status` command now correctly detects whether the firewall is active, even when other tools like Docker create additional chains.
- Coexistence mode: `stop` command now properly removes all FirewallFabrik chains, including sub-chains with hash-based names (e.g. `fwf_C...`) that were previously left behind ([#42](https://github.com/Linuxfabrik/firewallfabrik/issues/42)).
- Coexistence mode: `stop` command now properly removes FirewallFabrik's chains and jump rules on all systems, including those using the iptables-nft backend.
- Coexistence mode: `stop` command now restores chain policies to ACCEPT so that rules from other tools (Docker, CrowdSec, fail2ban) keep working after stopping the firewall.
- Compiler now generates IPv6 rules (ip6tables / nftables inet) based on the rule set's address family setting ("IPv4 and IPv6") instead of requiring IPv6 addresses on the firewall's interfaces ([#42](https://github.com/Linuxfabrik/firewallfabrik/issues/42)).
- Compiler error and warning messages now show the rule position number instead of the color label.
- IPv6 address and network dialogs now accept prefix lengths 0-128 instead of 1-127 ([#50](https://github.com/Linuxfabrik/firewallfabrik/issues/50)).
- Compiler no longer rejects TCPService objects with a string `'False'` value for the `established` option.
- Extra leading whitespace in generated iptables scripts from inline configlet `{{if}}` blocks removed.
- Generated iptables scripts now abort on `script_body` failure instead of continuing with an incomplete ruleset.
- Generated scripts use `command -v` instead of non-POSIX `which` for checking program availability.
- Harmless Qt/Wayland text-input warnings suppressed during GUI startup.
- Main window border is now clearly visible on GNOME/Wayland.
- `RETVAL` variable is now initialized at script start and set to `1` for invalid arguments.
- `stop_action` in generated iptables scripts now keeps chain policies at DROP instead of setting ACCEPT, preventing the server from being completely open after stop.
- Test infrastructure: expected output files are now also regenerated for firewalls with compiler warnings.


## [v1.3.0] - 2026-03-17

### Added

- Advanced Interface Settings dialog to configure device type (ethernet, VLAN, bridge, bonding), VLAN ID, STP and bonding parameters.
- `Alt+Return` keyboard shortcut opens the editor for the selected object (same as double-click).
- Appearance tab in Preferences — customize fonts for rules, tree and compiler output; toggle direction/action text, comment clipping and toolbar labels.
- Bridge interface configuration support for iptables and nftables using iproute2 (`ip link`).
- Bridge port interfaces are detected automatically from the parent interface type.
- Installer tab in Preferences — configure SSH/SCP paths, timeout and password caching for the built-in policy installer.
- Rules menu: insert, move, copy, cut, paste, remove, disable and enable rules directly from the menu bar.
- Tooltips on all widgets in the platform settings dialogs and the interface editor.
- VLAN sub-interface name validation — warns when the name does not match the parent interface.

### Changed

- About dialog: Linuxfabrik credit visually separated with homepage link (https://www.linuxfabrik.ch).
- Application icon uses PNG at multiple sizes for Wayland compatibility; window icon set via .ui file.
- Default label colors use the Solarized palette throughout; "Purple" renamed to "Cluster", "Gray" renamed to "Maintenance".
- Interface autoconfigure now also runs when opening the editor, not only on save.
- Platform settings dialogs: Script tab shows inline descriptions for each option; Help buttons removed; dialog size reduced.
- Policy rule table borders now match the fwbuilder look (native headers, subtle cell borders).
- Removed XCB/XWayland fallback; fwf runs natively on Wayland.
- Timestamps removed from generated shell scripts to ensure idempotent deployments.
- "Unprotected interface" checkbox removed from the interface editor (not applicable to iptables/nftables).

### Fixed

- Address containment: AddressRange objects were incorrectly treated as "any" address by the shadowing detector.
- Shadowing detection now produces warnings instead of aborting the compilation.


## [v1.2.0] - 2026-03-17

### Added

- Clickable compile log errors scroll to the relevant firewall section (closes #15).
- Cluster Member Management dialog to add/remove firewalls and view interface mappings (closes #26).
- File Properties dialog showing file path, size, and object counts (closes #29).
- Full Firewall Builder compiler parity for iptables and nftables (~130 rule processors ported).
- Import Addresses from File via Tools menu (closes #12).
- Inspect Rules showing all rules referencing the selected object (closes #28).
- Interface name autoconfiguration guesses type and VLAN ID from name patterns.
- Library Export to a separate `.fwf` file (closes #27).
- Library Import from `.fwf` or `.fwb` files.
- NFLOG logging target support for iptables and nftables (closes #18).
- nftables load balancing, address set merging, and separate shadowing pass (closes #22, #23, #24).
- Policy rules now use Preferences defaults for logging, stateful inspection, action, and direction.
- Preferences dialog with Restore Defaults, DNS Name, Address Table, Policy Rules, and Interface tabs.
- Standard service library: Bareos, Keycloak, Kibana, Libvirt, Logstash, OpenSearch.

### Changed

- Generated iptables scripts now run `nft flush ruleset` on systems where `nft` is available.
- Timestamp format in generated scripts changed to ISO 8601.

### Fixed

- "Advanced Interface Settings" button documented as intentionally disabled for iptables/nftables (closes #13).
- False-positive shadowing errors caused by analysis injecting rules into the main pipeline.
- Hardcoded version in generated iptables scripts replaced with the actual package version.
- MAC address edits were silently ignored (fixes #14).
- Multiport rules were broken: TCP flag check incorrectly matched all TCP services (fixes #21).
- Opening objects for editing no longer marks the file as modified when nothing changed (fixes #25).


## [v1.1.0] - 2026-03-16

### Added

- DiffServ (DSCP/TOS) matching for the nftables compiler (`ip dscp` / `ip tos`).
- DSCP symbolic class names (`AF11`, `EF`, `CS3`, etc.) now generate `--dscp-class` in iptables output, matching Firewall Builder behavior.
- Fragment matching (`-f` / `-m frag --fragmore`) and IPv4 option matching (`-m ipv4options`) in the iptables filter compiler (previously only present in the NAT compiler).
- Router-alert IP option (`--ra` / `--flags router-alert`) support in both iptables filter and NAT compilers.
- Tooltips for all IPService dialog fields (protocol number, DSCP, TOS, IP options, fragments).
- Version-aware `ipv4options` module formatting: old module (`--lsrr`, `--ra`) for iptables < 1.4.3, new module (`--flags lsrr,router-alert,...`) for >= 1.4.3.

### Changed

- DiffServ default changed from TOS to DSCP (the modern standard).
- DiffServ radio buttons unselected by default when no code is set; input field disabled until DSCP or TOS is chosen.
- Input widget borders use `palette(dark)` instead of `palette(mid)` for better visibility.

### Fixed

- Boolean flags stored as string `'False'` (truthy in Python) now stored as native booleans.
- DiffServ data keys now consistent across compilers and shadow detection.
- ICMP type/code matching in NAT rules now reads from the correct attribute.
- Rule shadowing false positives for IPService objects (e.g. VRRP) fixed.
- TagService data key inconsistency between dialog and display fixed.
- TCP flags in iptables compiler now read from ORM attributes instead of pre-formatted strings.


## [v1.0.1] - 2026-03-11

### Fixed

- Platform YAML defaults not included in pip-installed packages (missing `MANIFEST.in` entry).


## [v1.0.0] - 2026-03-08

### Added

- CLI compilers (`fwf-ipt`, `fwf-nft`) accept multiple firewall names and `--all` flag; database is loaded once for all firewalls.
- Collabora Online, Icinga, Nextcloud notify_push and WinRM added to the standard library.
- Compile time intervals and clean up time dialog.
- Confirm-delete dialog when deleting objects that are still in use.
- DNS "Resolve Name" button implemented for IPv4 and IPv6 address dialogs.
- DynamicGroup editor with criteria table and matched-objects preview.
- Example files shipped with the distribution.
- File > Reload action to re-read the current file from disk.
- FreeIPA service group added to the standard library.
- MIME type definitions for `.fwf` and `.fwb` files for file manager integration.
- NAT and Routing rule display support with title bar dirty-state indicator.
- Parallel compilation in the GUI: multiple firewalls compile concurrently using up to N CPU cores, with ordered log output.
- Platform and OS option defaults defined in YAML as single source of truth, replacing scattered hardcoded dicts.
- Settings dialogs now show tooltips and placeholder defaults from the YAML schema.
- Subfolder paste, drag & drop, and nested object creation in the object tree.
- System theme icons (Breeze, Adwaita, etc.) for toolbar and menu actions, with QRC fallback.
- Title labels on MDI rule set panels and Del key support for deleting rules.
- Undo stack entries prefixed with the device name for clarity.
- Window menu and automatic opening of firewall Policy on file load.

### Fixed

- `.fwb` imports allowed to compile and install without requiring a prior save.
- Clipboard router now correctly routes Ctrl+C/X/V to focused text widgets.
- Compiler option lookup (`get_option`) now raises `KeyError` on unknown keys, catching typos at the earliest possible moment; all inline Python fallbacks removed in favour of YAML defaults.
- Context menus and sub-interfaces aligned with fwbuilder behavior.
- Dead menu entries removed (File Compare, SNMP Discovery, Policy Import, Library Import/Export, Print, Help Contents/Index).
- DynamicGroup, AddressTable and DNSName now allowed in rule src/dst cells.
- Find & Replace scope, tree filter, element display, and MDI refresh.
- Focus moves to next element in a rule cell after deleting an object.
- ICMP type/code now read from the codes field instead of data.
- Keywords renamed to Tags in context menus.
- Last-active rule set persisted by name instead of UUID for stability across imports.
- Legacy Firewall Builder compiler paths (`fwb_ipt`, `fwb_nft`) detected during `.fwb` import; a dialog offers to clear them so FirewallFabrik uses its built-in compiler.
- Linux host settings now save under canonical `linux24_conntrack_*` keys matching the compiler.
- Lock/Unlock menu actions wired up to tree selection.
- MDI views refresh on object rename; undo descriptions are now human-readable.
- Model class name used instead of `.type` in `duplicate_object`.
- Netmask shown in tree when editing an address under an interface.
- New objects created via the toolbar menu now land in the selected custom folder.
- Nftables compiler now correctly generates `tcp flags != syn ct state new drop` rules when `accept_new_tcp_with_no_syn` is disabled (was reading a non-existent key).
- Object deletion fixed: str-vs-UUID type mismatch in where-used reference queries.
- Object tree auto-selects the Policy item when opening a file.
- ORM objects flushed before raw `rule_elements` INSERT to avoid integrity errors.
- Output pane context menu shows Ctrl+C and Ctrl+A shortcuts.
- Parent firewall `lastModified` timestamp updated on child/rule/shared-object edits.
- Readonly flag passed to tree items with updated lock icons.
- Rule shadowing detection enabled by default; error messages include rule position numbers.
- Time dialog uses YYYY-MM-DD date format and sensible defaults.
- Title bar double-click on Wayland now works (XCB fallback).

### Changed

- Decouple GUI components with ClipboardStore, PolicyViewBridge, and focus registration.
- Extract ClipboardRouter, EditorManager, and RuleSetWindowManager from FWWindow.
- Extract TreeActionHandler from ObjectTree.
- Extract context-menu builders from PolicyView into a dedicated module.
- Modernize UI with comprehensive QSS stylesheet.
- Object tree rewritten into 4 focused modules.
- Replace tree clipboard global with instance attribute and add paste validation.


## [v0.5.0rc1] - 2026-02-13

### Added

- CIDR notation parsing in IPv4/IPv6 editor dialogs and editor breadcrumb.
- Center compile dialog on screen and persist its geometry.
- Firewalls needing recompilation shown in bold in the object tree.
- Highlight only the clicked cell in rule view and protect default Any elements.
- Input validation and widget constraints for all editor dialogs.
- RuleSet editor dialog for Policy, NAT and Routing.
- Show asterisk in title bar when file has unsaved changes.

### Fixed

- Address range end field auto-filled when start field loses focus.
- Bool-coerced inactive flag from XML loader handled correctly.
- Compiler/installer remote paths and file names corrected.
- Context menu actions deferred to prevent SIGSEGV on tree clear.
- Compile, Install and Save actions disabled when no file is loaded.
- Default Qt icon replaced with the FirewallFabrik app icon.
- Deprecated Qt5 margin property removed from .ui files.
- Host OS Settings options disabled for unsupported nftables features.
- Platform Settings options disabled for unsupported compiler features.
- Qt5 signal/slot mismatch in the find panel .ui file corrected.
- Skip Any sentinel objects in rule element display.
- Warn before overwriting existing .fwf when saving an imported .fwb.

### Changed

- Erroneous QSS styling removed.
- Include .qss files in build output.


## [v0.5.0b1] - 2026-02-13

Initial public beta pre-release.

### Added

- Compile and install workflow for iptables and nftables platforms.
- Ctrl+Shift+N shortcut for File > New Object File.
- Ctrl+Shift+S shortcut for File > Save As.
- Detailed object tooltips ported from fwbuilder to the rule editor.
- File > Close (Ctrl+F4) to close the current document.
- Group dialog with drag & drop support.
- Host wizard dialog ported from fwbuilder.
- Library folder structure with nested group placement.
- MDI rule set windows with multi-select drag, clipboard, delete and context menu.
- Modernized Qt6 appearance with Fusion style and central stylesheet.
- nftables settings dialog.
- Object tree with Delete context menus and New [Type] for group-based folders.
- Panels hidden when no database file is loaded.
- Resource compilation from .qrc at build time.
- Restore last active object and MDI rule set when reopening a file.
- Rule number column display and platform combo defaults.
- Service library expanded with Wikipedia multi-service ports.
- Single-rule compile for the correct platform, with error for unsupported platforms.

### Fixed

- Accept new TCP with no SYN option corrected.
- Firewall modified timestamp updated when changing host/platform settings.
- Flush pending editor changes before save/close/switch.
- IPv4/IPv6 order option corrected.
- Object tree strikethrough and MDI titles refreshed on inactive toggle.
- Stub slots added for unimplemented .ui connections; unused UI elements disabled.

### Changed

- Fixture database caching with sqlite3 serialize/deserialize for faster tests.


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
