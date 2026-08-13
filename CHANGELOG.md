# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

**Highlights:** A large-scale correctness pass over both compilers. A whole class of rules that silently compiled into something other than what the GUI shows is now either compiled correctly or reported at compile time, instead of matching every address, every service, or nothing at all. Two of those are worth naming: a routing rule whose destination is a group, an address range or a host installed a default route out of the gateway meant for that one destination, sending all traffic the wrong way; and a block list whose file turned out to be empty or unreadable matched every address there is, so the rule blocked or permitted everything. Two more from the same pass: a rule the compiler had just reported as impossible to compile was installed anyway, without the condition it could not express, so "accept established connections to these ports" became "accept everything to those ports"; and on nftables a rule asking for policy routing was compiled into a rule that matched a packet mark and did nothing, silently dropping the route it was written for, where iptables refused the same rule by name. Every generated nftables ruleset loads and every generated script parses, both for the first time across the whole test corpus. On iptables, "Clear all rules" really clears them again, and dual-stack firewalls no longer carry a copy of every IPv6-only rule in their IPv4 chains. Most of this lands in cases a typical policy never reaches: recompiling 335 firewalls from real configurations leaves the iptables rules unchanged on all but one of them, while the nftables side, being the younger compiler, changes on roughly one in ten. Re-compile and review your rulesets after updating, and read the breaking change below before you do.

### Breaking Changes

* A rule set that is not the firewall's top rule set is compiled into a chain of its own on both platforms and only runs when a rule with the Branch action jumps to it, the way Firewall Builder has always compiled it. Until now its rules were installed in the input, output and forward chains and applied to all traffic, which turns a branch that accepts into a hole in the firewall. Review every additional Policy or NAT rule set after updating: merge it into the top rule set if it is meant to apply everywhere, or point a rule with the Branch action at it if it is meant to be a branch.
* A rule set that sets neither "IPv4" nor "IPv6" is compiled for IPv4 only, the way Firewall Builder has always read that state. Until now such a rule set was compiled into the IPv6 ruleset as well. If one of them carries IPv6 rules, those rules disappear from the generated script: open the rule set in the editor and set it to "IPv4 and IPv6" to keep them.

### Changed

* FirewallFabrik installs on Python 3.11 and newer, so current distributions no longer need a custom Python build for it.
* The nftables firewall settings no longer show three options that only ever applied to iptables. A firewall switched back to iptables keeps its values.

### Added

* Compiler (iptables, nftables): the "Limit matching rate" rule options that keep their counts per source, destination or port are compiled ([#121](https://github.com/Linuxfabrik/firewallfabrik/issues/121)).
* Compiler (iptables, nftables): the "Limit number of simultaneous connections" rule option is compiled ([#120](https://github.com/Linuxfabrik/firewallfabrik/issues/120)).

### Fixed

* Compiler (nftables): a message about a rule is written into the generated ruleset with one comment marker instead of two, and a rule with more than one message keeps every line inside its chain block.
* Compiler (nftables): a rule whose rate limit names a unit the compiler cannot read is left out instead of being compiled per second. A rate written per minute was enforced sixty times as often, and iptables left the same rule out already. A burst larger than nftables can carry is reported too: it was cut down without a word, and a burst of exactly 4294967296 became five.
* Compiler (nftables): a rule whose packet mark, traffic class or connection mark cannot be written out is left out instead of being installed without it. The rule kept its conditions and lost the marking it exists for, so everything keyed on that mark - a routing decision, a traffic class, another rule - saw traffic the policy says is marked and found it was not. iptables left such a rule out already.
* Compiler (nftables): a rule whose action cannot be written out is left out instead of being installed as a plain packet counter. A rule with the Branch action pointing at a rule set nftables cannot jump to, and one with a Custom action, kept all of their conditions and lost the action, so the packet fell through to whatever rule came next while the activation reported success. iptables left such a rule out already.
* Compiler (nftables): a rule asking for policy routing is reported and left out, the way iptables already refuses it. It was compiled into a rule that matched a packet mark and did nothing, so the route the rule was written for was silently gone and the same file behaved differently on the two platforms ([#125](https://github.com/Linuxfabrik/firewallfabrik/issues/125)).
* Compiler (nftables): a rule whose connection limit groups by more bits than the address family has is reported and left out, the way iptables already reports it. The grouping was silently dropped and the limit then counted per single address, so the same policy enforced two different limits on the two platforms.
* Compiler (nftables): a NAT rule naming an interface or a host that carries no address is reported and left out instead of ending the compile with an internal error and no script at all.
* Compiler (nftables): a NAT rule that excludes an IP service matching on more than one thing is reported and left out. Only the protocol was inverted and the other conditions were written out unchanged, so the rule translated part of exactly the traffic it excluded.
* Compiler (nftables): a logging rule that keeps its own connection limit or rate limit stays one rule on a firewall that rate-limits its log messages. It was compiled into a log rule and a verdict rule that both carried the limit, and a limit is counted on every rule a packet crosses, so half the traffic the rule was meant to stop passed it.
* Compiler (nftables): a rule naming two address tables, DNS names or dynamic interfaces on the same side is compiled as one rule per object. They were written into a single rule, which asks for a packet whose address is in two lists at once: no packet is, so a Deny rule stopped nothing and an Accept rule let nothing through. The compiler reported it and left the rule out since the last release; now the rule is compiled.
* Compiler (iptables, nftables): a rate limit table named by rules in more than one rule set is reported. The check only ever looked inside a single rule set, so the most common case went unnoticed: on iptables the kernel hands every later rule the first one's rate and key, and on nftables two rules asking the same table for different keys make the whole ruleset fail to load.
* Compiler (iptables): a firewall pinned to an iptables older than 1.4.3 writes a negated connection limit the way that release takes it. The rule went out with the newer spelling, which those releases refuse outright, stopping the activation script and leaving every rule after it uninstalled. Every other negatable option was already written this way.
* Compiler (iptables): a log level stored as "err" or "warn" is written out as "error" and "warning". Those are the names nftables uses; iptables answers them with 'log level "err" unknown', which stopped the activation script and left every rule after it uninstalled.
* Compiler (iptables): a rate limit whose unit is abbreviated ("/sec", "/min") is compiled the same way nftables compiles it. The abbreviation was passed on unread, so the rate was measured against the wrong ceiling and a legal rate could be refused; a suffix naming no unit at all reached the activation script and stopped it with "bad rate".
* Compiler (iptables): a rate limit kept per source, destination or port is checked against the ceilings of the release the firewall is pinned to. Releases before 1.6.1 accept a hundredth of the rate and of the burst, so a value between the two ceilings stopped the activation script with "Rate too fast" and left every rule after it uninstalled.
* Compiler (iptables): the name of a rate-limit table is checked before it reaches the activation script. The name went into the command unquoted, so a name holding shell syntax ran as a command on the firewall, as root, at the moment every chain is already set to drop.
* Compiler (iptables, nftables): a rule the compiler reports as impossible to compile is left out of the script instead of being installed anyway. A service with the "established" option lost that condition and accepted every packet to those ports, and an object that failed to resolve left its side of the rule matching every address.
* Compiler (iptables, nftables): a routing rule whose gateway is an interface or a host that also carries a MAC address installs its route. The MAC was counted as a second address, so the rule was reported as having an ambiguous next hop and left out - which happens to every gateway on a host with "MAC address matching" turned on.
* Compiler (iptables, nftables): the "Data directory" setting is used for an address table that is read on the firewall. A file name holding %DATADIR% kept that literal text in the generated script, so the firewall looked for a directory of that name and the table stayed empty. The setting is now offered on nftables firewalls too, which read such tables the same way.
* Compiler (iptables, nftables): the "Output file name" setting is honoured when compiling from the command line, not only from the GUI. A scripted or scheduled compile wrote the name derived from the firewall object instead, so the installer copied a different file than the one that had just been generated.
* Compiler (iptables, nftables): an accepting rule of a packet-marking rule set is placed in the prerouting chain, the way Firewall Builder places it, so it is reached on every path through the firewall instead of only on the one its direction names.
* Compiler (iptables, nftables): a firewall whose packet forwarding is set to "Off" no longer gets forward-chain rules, the way Firewall Builder has always compiled it. The rules were installed and could never match, and would start matching the moment somebody turned forwarding on outside the firewall script.
* Compiler (iptables, nftables): the automatic rules of a dual-stack firewall ask the forwarding setting of the family they are for. Both families were decided by the IPv4 switch, so a firewall that routes IPv6 but not IPv4 lost its automatic IPv6 forward rules, and one that routes IPv4 but not IPv6 got IPv6 rules it cannot use.
* Compiler (iptables): the ToS value of an IP service is checked before it reaches the activation script. An unreadable value stopped the script with every chain already set to drop, and a value holding shell syntax ran as a command on the firewall, as root, at that same moment.
* Compiler (iptables, nftables): a ToS or DiffServ value written in octal is read the way both packet filters read it, instead of being reported as invalid and costing the rule.
* Compiler (iptables): a NAT rule that does not match on an interface is no longer left out because of that interface's name. A name too long for the kernel cost the rule even where it was never written, and a rule split for a negation lost only one of its two halves, which changes what the other half matches.
* Compiler (iptables): a redirecting NAT rule with the "Persistent" option names the REDIRECT target in its message instead of MASQUERADE, so it points at the rule the administrator has to change.
* Compiler (iptables): a NAT rule matching a bridge port says which bridge it means on a firewall with more than one. Two bridges sharing a wildcard port name - what libvirt gives a host with several virtual networks - could not be told apart, so a rule written for one bridge also translated the other bridge's guests. Policy rules named the bridge already.
* Compiler (iptables): an IPv6 rule matching fragments is compiled for the iptables release the firewall is pinned to. The fragment match reached ip6tables in 1.2.7; before that the command failed to load and stopped the activation script, leaving every rule after it uninstalled.
* Compiler (iptables): a rule whose Tag Service sets a mark with a mask is compiled for the iptables release the firewall is pinned to. Releases before 1.4.1 read the argument as a plain number and answer the "/" with "Bad MARK value", which stopped the activation script and left every rule after it uninstalled.
* Compiler (iptables): a rule whose marking, traffic class or custom action cannot be written out is left out instead of being installed with all of its conditions and no action. iptables takes such a rule as a plain packet counter, so the activation script ran to the end and nothing said the action had been dropped.
* Compiler (iptables): a rule whose IP service names a traffic class iptables cannot read is left out instead of being compiled without it. The rule kept its action and lost the condition, so "accept only AF41" became "accept everything" and "log only EF" logged the whole link. nftables left such a rule out already.
* Compiler (iptables): a rule whose "Limit matching rate" cannot be written out is left out instead of being written without it. The rule kept its action and lost its condition, which is the opposite of what it says: "drop above 20 per second" became "drop", and "accept up to 20 per second" became "accept everything".
* Compiler (iptables): "Clear all rules" really clears them on current distributions. The firewall kept its old rules and grew with every activation, with all traffic blocked in the meantime.
* Compiler (iptables): a logging rule whose prefix consists only of characters the generated script cannot pass on activates. It went out as an empty prefix, which iptables refuses, stopping the activation script and leaving every rule after it uninstalled; the rule now logs without a prefix and says so.
* Compiler (iptables): a log prefix longer than the LOG or NFLOG target can carry is reported instead of being cut silently. nftables has room for the whole string, so the same policy wrote differently shaped log lines on the two platforms.
* Compiler (iptables): a NAT rule with the "Persistent" or "Random" option is compiled for the iptables release the firewall is pinned to. Firewalls pinned to 1.4.3 or older got an option that release does not know, which stopped the activation script and left every rule after it uninstalled.
* Compiler (iptables): a firewall that keeps other tools' rules and activates through iptables-restore declares its chains under the names its rules use. The declaration left the prefix off, so iptables-restore stopped at the first rule pointing into such a chain and none of the ruleset was loaded.
* Compiler (iptables): a firewall that activates through iptables-restore writes its chain lines so the shell cannot rewrite them. A file named "0" or ":" in the directory the activation script runs from turned the packet counters into a glob, and iptables-restore then stopped at the first chain with all traffic already blocked.
* Compiler (iptables): a rule matching IP header options says that the "ipv4options" match it needs is not part of iptables and comes from xtables-addons, instead of producing a rule that fails to load on a firewall without that package. A rule asking for loose and strict source routing at once is reported and left out on releases whose module refuses the combination.
* Compiler (iptables): a Reject rule whose reject type the pinned iptables does not know yet keeps the target's default type and says so, instead of stopping the activation script with "unknown reject type" and leaving every rule after it uninstalled. The two ICMPv6 types for a failed policy and a rejected route reached ip6tables in 1.6.0.
* Compiler (iptables): a NAT rule with the Branch action jumps into the chains the branch really uses, instead of being copied into prerouting and postrouting with a warning. The copy in the wrong chain carried a translation that chain cannot perform ([#90](https://github.com/Linuxfabrik/firewallfabrik/issues/90)).
* Compiler (iptables): a firewall that keeps other tools' rules ("Flush entire ruleset" off) manages its NAT and packet-marking rules the same way as its filter rules. Those two went into the shared PREROUTING and POSTROUTING chains, where the script could not find them again: every activation added another copy of them, and the marking rules were never reached at all.
* Compiler (iptables): a firewall pinned to an iptables older than 1.4.17 reports its IPv6 NAT rules instead of writing them into the script. That release brought NAT to ip6tables; before it there is no IPv6 NAT table at all, so the command failed to load and stopped the activation script, leaving every rule after it uninstalled. nftables is unaffected.
* Compiler (iptables): a rule using the "dstlimit" variant of the rate limit says that the match is gone from iptables since 1.3.8 and names the option to use instead, rather than producing a rule that stops the activation script.
* Compiler (iptables): a rule matching an address table through ipset is left out on a firewall pinned to an iptables that has no such match, with a message, instead of stopping the activation script and leaving every rule after it uninstalled. The ipset match reached ip6tables only in 1.4.9.
* Compiler (iptables): a dual-stack firewall pinned to an older iptables no longer gets IPv6 rules with matches that release only had for IPv4. The ToS, DiffServ, address-table, address-range and time-of-day matches reached ip6tables between 1.4.0 and 1.4.9; before that the generated ip6tables command failed to load and stopped the activation script, leaving every rule after it uninstalled. An IPv6 address range is written out as the networks covering it there, the way an old iptables already got it; a time restriction is reported. A firewall pinned before 1.3.7 logs through LOG instead of NFLOG for the same reason.
* Compiler (iptables): a dual-stack firewall pinned to an older iptables reports the IPv6 rules whose target that release only had for IPv4, instead of writing a command ip6tables refuses. Assigning a traffic class needs ip6tables 1.4.0 and saving a mark to the connection needs 1.3.5; before those the command stopped the activation script and left every rule after it uninstalled. nftables is unaffected.
* Compiler (iptables): a firewall pinned to iptables older than 1.2.11 matches an address range through the networks covering it, the way Firewall Builder always did. That release brought the range match; before it the generated command failed to load and stopped the activation script.
* Compiler (iptables): a NAT rule whose original destination is a host with only a MAC address is left out with an error, instead of being installed without the destination match, where it translated every address the rest of the rule allowed. nftables can match the destination MAC and does.
* Compiler (iptables): a NAT rule whose original service lists more ports than one match can carry activates. The last of the rules it is split into named the multiport module without giving it a port, which iptables refuses, stopping the activation script and leaving every rule after it uninstalled.
* Compiler (iptables): a rate limit higher than iptables can express is reported at compile time instead of stopping the activation script. nftables is unaffected.
* Compiler (iptables): a firewall pinned to an iptables older than 1.4.3 writes a negation the way that release takes it. The two spellings changed places in 1.4.3 and no release accepts both, so a rule negating a tag, a connection owner or an address was refused and stopped the activation script, leaving every rule after it uninstalled. This deliberately differs from what Firewall Builder generated for those firewalls.
* Compiler (iptables): a rule matching a host with "MAC address matching" turned on activates when it lands in a chain that cannot see a MAC. The kernel offers that match on the input path only, so the command was refused, which stopped the activation script and left every rule after it uninstalled. Such a rule now keeps its address condition and loses only the MAC, with a warning, the way Firewall Builder has always compiled it.
* Compiler (iptables): a rule that excludes a bridge port excludes it. The exclusion was dropped, so the rule matched exactly the traffic it was written to skip and everything else went unmatched - without any error at activation time.
* Compiler (iptables): a rule that excludes a MAC address activates. The negation was written in front of the match module instead of in front of the option, which iptables refuses outright, stopping the activation script and leaving every rule after it uninstalled. NAT rules were affected as well.
* Compiler (iptables): a DNAT rule naming several translated destinations spreads the connections over all of them. Each backend got a rule of its own, and because a NAT rule ends the chain, every connection went to the first one and the others received nothing. Backends that do not form one contiguous range are now reported, as Firewall Builder does.
* Compiler (iptables): a NAT rule that excludes an address range excludes it. The range is written out as the networks covering it, and each of those carried the exclusion on its own, so a packet from inside the range matched the first of them and the rule translated exactly the traffic it was written to leave alone. Policy rules were compiled correctly all along; nftables is unaffected.
* Compiler (iptables): a rule negating a single address, a single address table matched through ipset, or a single tag or connection owner uses the negation iptables has, instead of three rules and a helper chain that say the same thing. A negated address range keeps the helper chain: on releases that write a range out as the networks covering it, negating each of those networks on its own matches nearly everything.
* Compiler (iptables): a rule set or branch whose name iptables cannot use as a chain name is reported at compile time instead of failing during activation, including a name that one of the 42 iptables targets already has, such as "SNAT" or "LOG". nftables is unaffected.
* Compiler (iptables, nftables): a rule with the Branch action jumps to the rule set it names instead of matching traffic and doing nothing. A branch into the firewall's top rule set, or into a rule set of another firewall object, is still reported as unsupported ([#90](https://github.com/Linuxfabrik/firewallfabrik/issues/90)).
* Compiler (iptables): a rule whose time restriction is negated is compiled instead of being left out, so a policy that applies outside a time window works again.
* Compiler (iptables): an address table file that lists both IPv4 and IPv6 addresses gives each ruleset only the addresses that ruleset's tool accepts, so rules built on such a table are no longer missing from the running firewall.
* Compiler (iptables): bridging firewalls whose rules use an interface as a destination compile again instead of failing with an internal error and no script at all.
* Compiler (iptables): firewalls pinned to iptables 1.2.5 or to 1.2.6 through 1.2.8 are compiled for that release again.
* Compiler (iptables): firewalls that activate through iptables-restore and log invalid packets load their ruleset again instead of stopping at the first invalid-state rule.
* Compiler (iptables): firewalls that do not pin an iptables version are compiled for current iptables. Rules with a negated address or interface failed to load.
* Compiler (iptables): firewalls with routing rules generate a working script. One packet filter rule and the first route were lost.
* Compiler (iptables): IPv6 NAT rules that match a specific ICMPv6 type produce a valid rule.
* Compiler (iptables): IPv6 NAT rules whose original service matches fragments or IPv4 header options load instead of stopping the activation script, which left every rule after them uninstalled.
* Compiler (iptables): NAT rules whose original service matches ICMP as a whole load instead of stopping the activation script, which left every rule after them uninstalled.
* Compiler (iptables): log prefixes are written correctly on firewalls that activate through iptables-restore. Log messages ran into the packet data and broke log parsers.
* Compiler (iptables): masquerading rules that also translate the source port keep the configured port range instead of letting the kernel pick a port.
* Compiler (iptables): NAT rules translating into a port range that names only one of its two bounds load instead of stopping the activation script. nftables wrote the working form already.
* Compiler (iptables): NAT rules whose translated address cannot be determined are reported and left out instead of stopping the activation script half way.
* Compiler (iptables): rules combining a TCP flag or IP option match with a rate limit or a time restriction load again. They were missing from the running firewall.
* Compiler (iptables): rules that assign a traffic class do so. Traffic shaping never saw the class.
* Compiler (iptables): rules that set a mark, a traffic class or a route and list several addresses or services set it only for those. The mark was set on every packet the rule's other conditions matched, and the listed addresses and services were never checked at all.
* Compiler (iptables): rules that match an address table read on the firewall carry that match. Every such rule was left out, so a policy built around a block list did nothing at all. With the ipset module the rule uses the named set, otherwise it is written once per address in the file.
* Compiler (iptables): rules that match the address of a dynamic interface are filled in at activation time instead of running with an empty address. iptables rejected such a command, so the activation stopped there; a rule on a wildcard interface such as "ppp*" now covers every interface it matches.
* Compiler (iptables): rules that name an interface and apply in both directions no longer stop the activation script.
* Compiler (iptables): rules that reject with a TCP reset also work when they are logged or negate their source, destination or service. The traffic fell through to the rule below instead.
* Compiler (iptables): rules that reject with a TCP reset and cover a non-TCP service reject it with the default ICMP message instead of stopping the activation script, which left every rule after them uninstalled.
* Compiler (iptables): rules that use a custom service load again instead of being rejected for a missing protocol match.
* Compiler (iptables): the `--xp` rule trace works on firewalls imported from a `.fwb` file instead of aborting the whole compile with an internal error.
* Compiler (iptables): the automatic MSS clamping and connection mark rules survive activation on firewalls that activate through iptables-restore. They were wiped again right after being set.
* Compiler (iptables): the generated script no longer creates and fills chains nothing ever jumps to. Dual-stack firewalls carried a copy of every IPv6-only rule in their IPv4 chains and vice versa.
* Compiler (iptables): the generated script no longer tries to create a chain named after the NFLOG or ULOG target on firewalls that log that way. iptables refuses such a name, so the command failed on every activation.
* Compiler (iptables): the generated script waits at most five seconds for the iptables lock instead of blocking forever, which stalled unattended rollouts without an error.
* Compiler (iptables): the NFLOG "Copy range" setting takes effect, so the logging daemon receives only as much of each packet as the firewall asks for instead of always the whole one. Firewalls pinned to an iptables older than 1.6.1, which cannot express this, get a warning.
* Compiler (iptables): time-restricted rules load on firewalls pinned to an older iptables release.
* Compiler (iptables, nftables): "Add rules to permit IPv6 Neighbor Discovery" generates those rules. Dual-stack firewalls that drop by default lost IPv6 connectivity.
* Compiler (iptables, nftables): "Add virtual addresses for NAT" adds them, so a NAT rule that translates to a spare address of an attached segment works instead of dying in the ARP resolution the firewall never answers ([#143](https://github.com/Linuxfabrik/firewallfabrik/issues/143)).
* Compiler (iptables, nftables): a branching rule imported from a `.fwb` file finds the rule set it points at. Firewall Builder records that rule set by an internal identifier the import dropped, so the branch had no target.
* Compiler (iptables, nftables): a NAT rule with the Branch action that sits in a branch rule set itself jumps from that rule set's chain instead of from the built-in one, where it ran on all traffic.
* Compiler (iptables, nftables): a NAT rule with the Branch action imported from a `.fwb` file branches. Firewall Builder writes that action under a name the import did not know, so the rule was read as an ordinary translation rule: the branch was never taken, and the rule instead translated using the addresses Firewall Builder ignores on a branch rule.
* Compiler (iptables, nftables): a rule that excludes every interface the firewall has is left out with a message. Nothing was left for it to match on, and an interface condition that matches nothing reads as "on any interface", so the rule applied on exactly the interfaces it was written to skip.
* Compiler (iptables, nftables): a bridge port is recognised as one, so the generated script no longer tries to configure an address on it and rules that name one are compiled again.
* Compiler (iptables, nftables): a dual-stack interface or host is matched by its IPv4 address in the IPv4 ruleset and by its IPv6 address in the IPv6 one, instead of always the first. A single-stack object is left out of the other family instead of producing a ruleset that does not load.
* Compiler (iptables, nftables): a firewall whose rule sets produce no rules at all generates a script that runs instead of one the shell refuses to parse.
* Compiler (iptables, nftables): a rule matching on an interface whose name is longer than 15 characters is reported at compile time. Neither tool takes such a name, and the kernel cannot have one either, so the rule stopped the activation script or made the whole nftables ruleset fail to load.
* Compiler (iptables, nftables): the backup SSH rule of the "block" and "stop" actions works with an IPv6 management address. Both platforms wrote it as an IPv4 match, so the command failed at the one moment it matters: right after every chain has been set to drop.
* Compiler (iptables, nftables): a message about a rule names the rule set it belongs to. Every rule set numbers its rules from zero, so "Rule 0" pointed at as many rules as the firewall has rule sets and the reader had no way to tell which one the compiler meant.
* Compiler (iptables, nftables): a message about a rule appears once instead of twice. The compiler renders every rule a second time to find duplicates, and reported everything it found on the way again; a rule that was then dropped as a duplicate still counted as an error.
* Compiler (iptables, nftables): a NAT rule naming a host with "MAC address matching" turned on matches the address and the MAC together, instead of whichever of the two came first. It translated for every host carrying that MAC. A NAT rule whose addresses carry nothing to match on is reported and left out, instead of translating everything the rest of the rule allowed.
* Compiler (iptables): a NAT rule whose Original Destination is a host with "MAC address matching" is compiled with that host's address. The whole object was thrown away with a "could not resolve" message, so a rule with a perfectly good destination was left out; iptables can only match a source MAC, and now says so while keeping the address.
* Compiler (iptables, nftables): what the compiler reports about a NAT rule appears in the generated script next to that rule, the way it already did for a policy rule. A message that only reached the compiler output was gone by the time somebody read the file.
* Compiler (iptables, nftables): a NAT rule matching on a bridge port matches the port. A bridged packet carries the bridge, not the port, in the field the rule was reading, so the rule never fired and the traffic was not translated. On iptables the port is matched through "physdev" the way a policy rule matches it; nftables cannot see a bridge port in a NAT table and says so.
* Compiler (iptables, nftables): a NAT rule whose Original Service inspects the TCP flags matches on them. It translated every TCP packet between the addresses it named instead of the handshake stage it was written for. A NAT rule whose service matches on the ToS or DSCP field is reported and left out; neither packet filter can carry that condition on a NAT rule, and it was silently dropped.
* Compiler (iptables, nftables): an address table or DNS name object that yields no address at all is reported and the rule left out. The object was silently removed instead, and a rule element with nothing left in it means "any": a rule written for the addresses in a block list matched every address there is, so a Deny rule blocked all traffic and an Accept rule opened the firewall.
* Compiler (iptables, nftables): an address table or DNS name object used inside a group is read. It was dropped on the way out of the group, so a rule combining a block list with a single host only ever matched that host, and a group holding nothing but such objects was reported as empty.
* Compiler (iptables, nftables): a routing rule installs a route to every destination it names. A destination given as a group, an address range or a host was thrown away and the rule became a **default route** out of the gateway and interface meant for that one destination, so all traffic left the firewall the wrong way. A destination the compiler cannot turn into an address is now reported and the rule left out, and a rule naming neither a gateway nor an interface, a gateway carrying more than one address, an interface of another object or a network whose address does not match its own netmask is reported as well.
* Compiler (iptables, nftables): a routing rule uses the "path to ip" the firewall configures, and an IPv6 route says so. A route to "default" that names only an interface went into the IPv4 table whichever family it was written for.
* Compiler (iptables, nftables): a rule whose addresses all belong to the other address family is left out of the ruleset with a message. It was compiled without those addresses instead, which reads as "any": a rule for a handful of named hosts became a rule for every address there is, and on a rule that accepts, that is a hole in the firewall.
* Compiler (iptables, nftables): a rule matching IP header options is left out of the IPv6 ruleset with a message instead of being installed without that condition. IPv6 has no option field, so the rule applied to every packet: on a rule that accepts, that is a hole in the firewall.
* Compiler (iptables, nftables): a rule whose rate limit is negated ("not more often than" turned around) is compiled as written. The negation was read by nobody, so the rule fired below the rate instead of above it, doing the opposite of what the editor shows. nftables expresses it natively; iptables has no inverted rate limit and now reports the rule.
* Compiler (iptables, nftables): a NAT rule whose original service is a Custom Service carrying no code for the platform is reported instead of compiled without it. On nftables the rule disappeared without a word, so the traffic it was written to translate crossed the firewall untranslated. Policy rules were checked all along.
* Compiler (iptables, nftables): a NAT rule whose original service lists several ICMP types, IP protocols, custom services, tags or connection owners translates all of them instead of only the first. The rest were silently dropped, so that traffic left the firewall untranslated. Policy rules were already split this way.
* Compiler (iptables, nftables): a NAT rule that maps a whole network 1:1 keeps translating every protocol. If the rule also named a translated service, the generated rule was narrowed to that service's protocol, so everything else crossed the firewall untranslated.
* Compiler (iptables, nftables): a NAT rule whose translated service uses a different protocol than the original is reported instead of being compiled into a translation the rule does not ask for.
* Compiler (iptables, nftables): a log prefix holding a double quote, a dollar sign, a backtick, a backslash or a control character is reported and written without it. Such a prefix broke the nftables ruleset outright, and on iptables the shell running the activation script expanded it: at best the logged text was wrong, at worst the prefix ran a command on the firewall. The rule set and interface names the prefix macros splice in are covered too.
* Compiler (iptables, nftables): a Reject rule that rejects with a TCP reset and matches any service rejects with the default ICMP message instead, and says so. A TCP reset only exists for TCP: iptables refused the rule outright, which stopped the activation script and left every rule after it uninstalled, and nftables quietly narrowed the rule to TCP, so everything else it was written to reject passed.
* Compiler (iptables, nftables): a Reject rule sends back the ICMP message its reject type names on both platforms. nftables fell back to a plain reject for the three IPv6 types imported from a `.fwb` file that it can express perfectly well, so the sender was told the wrong reason.
* Compiler (iptables, nftables): a NAT rule matching the connection owner in the prerouting chain is dropped with a warning instead of being installed. The kernel refuses that match on a hook where the packet has no socket yet, which stopped the activation script and left every rule after it uninstalled.
* Compiler (iptables, nftables): a masquerading NAT rule with the "Persistent" option activates. iptables has no such option for masquerading and refused the command, which stopped the activation script and left every rule after it uninstalled; the option is now left out there with a warning, and applied on nftables, which can express it.
* Compiler (iptables, nftables): a rule naming a host whose MAC address is empty is left out with a warning naming the object, instead of iptables matching an all-zero MAC no packet ever carries.
* Compiler (iptables, nftables): a rule naming a host with "MAC address matching" turned on matches the MAC again, together with that host's address. The MAC was left out of the rule, so it applied to whoever used the address; on nftables a rule listing MAC-only and ordinary hosts side by side asked for all of them at once instead of any of them.
* Compiler (iptables, nftables): a rule matching a MAC address in a chain where the packet no longer carries one is reported at compile time instead of stopping the activation script, and a rule matching the connection owner is kept in the POSTROUTING chain, where the kernel accepts it.
* Compiler (iptables, nftables): a source translation to an unnumbered interface is reported instead of stopping the activation script on iptables and translating to the wrong address on nftables.
* Compiler (iptables, nftables): address ranges are no longer emitted into the wrong address family, which produced a ruleset that did not load.
* Compiler (iptables, nftables): an IP service with an unknown DiffServ class name, or a code point above 63, is reported with a clear error instead of producing a ruleset that does not load. Writing "EF" as the traffic class byte 184 is the usual way into this.
* Compiler (iptables, nftables): an IPv6 network with a /32 netmask is matched as the whole prefix again instead of as a single address, so a rule written for a provider allocation covers it.
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
* Compiler (iptables, nftables): a rule whose address table could not be read is left out instead of matching every address. An "accept from this table" rule accepted from everywhere.
* Compiler (iptables, nftables): the check for rules that can never fire reports three cases it used to miss, among them an "accept everything" above a "deny everything" and a rule whose address is a host or a group; it also names the rule set of each rule, so a finding in one branch no longer hides the same finding in another.
* Compiler (iptables, nftables): the check for rules that can never fire no longer reports a rule as covered by one above it that only fires at a limited rate.
* Compiler (iptables, nftables): the connection-tracking settings are applied. A firewall that also tunes a kernel hardening setting wrote the last of those settings to a non-existent file and skipped the connection-tracking table size entirely.
* Compiler (iptables, nftables): the firewall-wide limit on log messages reaches the generated ruleset. A logging firewall under load could fill its disk.
* Compiler (iptables, nftables): the rule that logs invalid packets through NFLOG obeys the "Copy range" and "Queue threshold" settings. iptables also stops printing a warning about a no-op option on every activation.
* Compiler (nftables): activating a firewall whose ruleset nftables refuses keeps the rules that are running instead of leaving the host with none. The script flushed first and loaded afterwards, so any rejected ruleset - one rule nftables cannot parse is enough, and it refuses all of it - left the firewall wide open. The generated script now asks nftables to check the ruleset first and stops with a message if it does not pass.
* Compiler (nftables): a branch rule set that marks or classifies packets gets a chain of its own in the mangle table as well, and runs only where a rule with the Branch action jumps to it. Its rules were installed in the hooked mangle chains, which run before the packet filter: a branch that drops turned the firewall into a black hole, and a branch that marks marked traffic it was never meant to see.
* Compiler (nftables): a branch NAT rule set gets a chain of its own and runs only where a rule with the Branch action jumps to it. Its rules were installed in the shared prerouting and postrouting chains, ahead of the ones the top rule set has, so they translated all traffic; the branching rule itself accepted everything and turned off translation for the rest of the connection ([#90](https://github.com/Linuxfabrik/firewallfabrik/issues/90)).
* Compiler (nftables): a firewall with weekday-restricted rules is warned when its time zone setting makes iptables and nftables pick different days. The warning was the wrong way round and fired exactly when the two agreed.
* Compiler (nftables): a firewall whose only rules are the automatic ones installs them together with its default-drop policy, instead of an empty ruleset that left the host open.
* Compiler (nftables): a NAT rule for an ICMP service translates only the message types it names instead of every ICMP packet between the addresses in the rule.
* Compiler (nftables): a NAT rule marked "Use MASQUERADE target" masquerades, as the same rule does on iptables. The setting was ignored and the traffic was translated to a fixed address instead, which breaks as soon as the outgoing interface gets a different one.
* Compiler (nftables): a rule matching a MAC address in the output chain is reported instead of being installed. A packet the firewall sends itself has no ethernet header there, so the rule never matched: a Deny rule let the traffic through and an Accept rule had it dropped by the chain policy, with nothing said about it. The check now covers the destination side and hosts reachable only by their MAC, not just a bare MAC address object in the source.
* Compiler (nftables): a NAT rule naming a host with "MAC address matching" turned on is compiled instead of being reported as an address the compiler cannot resolve. Every such rule was left out of the ruleset, so the traffic it was written to translate crossed the firewall untranslated; iptables had those rules all along.
* Compiler (nftables): an SNAT rule whose destinations sit behind different interfaces translates for all of them. Every destination got the interface and the address of the first one, so the rest could never match and that traffic crossed the firewall with its private source address. iptables split such a rule all along.
* Compiler (nftables): a NAT rule whose original service list mixes services that restrict the source port with services that do not is compiled into one rule per source port. The restriction was either dropped, so the rule translated traffic from any source port, or applied to the other services as well, so their traffic was no longer translated at all. A service covering a whole protocol ("All TCP") next to a specific port keeps covering the whole protocol. iptables split these rules all along.
* Compiler (nftables): a NAT rule that excludes a group of addresses excludes all of them instead of still translating every one.
* Compiler (nftables): "Clamp MSS to MTU" clamps both directions of a forwarded connection. The rule sat behind the automatic accept for established connections, so only the first packet of a connection was clamped and the answer of the server kept announcing a segment size the path cannot carry - the very case the setting exists for on a PPPoE, GRE or WireGuard link.
* Compiler (nftables): a NAT rule matching on an interface whose name is too long is left out, as the same rule in the packet filter already was. nftables refuses such a name and throws away the whole ruleset over it, so one NAT rule kept the firewall from loading any of its rules.
* Compiler (nftables): a NAT rule matching on an interface whose name holds a double quote produces a ruleset that loads, as a policy rule already did. nftables knows no escape inside a quoted string, so the name ended the string early and the rest of the ruleset was read as syntax.
* Compiler (nftables): a logging rule whose severity is "panic" or a number produces a ruleset that loads. nftables knows neither spelling and refused the whole ruleset over it, so the firewall kept its old rules; a severity it cannot express at all is now reported and the rule logs at the default level.
* Compiler (nftables): a NAT rule that translates a port and excludes an IP protocol produces a ruleset that loads. nftables does not carry the protocol forward across an exclusion, so it refused the port translation and with it the whole ruleset, which leaves the firewall on its old rules.
* Compiler (nftables): a NAT rule that masquerades into a port range produces a ruleset that loads. nftables needs the protocol named before a port translation, and the rule got it for every kind of translation except masquerading; a rejected ruleset means the firewall keeps its old rules.
* Compiler (nftables): a NAT rule that translates into an address range and a port range produces a ruleset that loads. It was written in a form nftables rejects, and a rejected ruleset means the firewall keeps its old rules.
* Compiler (nftables): a NAT rule that translates the source and the destination is labelled in both chains of the generated ruleset, so its second half is no longer filed under an unrelated rule number.
* Compiler (nftables): a rule set whose name is one of the chain names the generated ruleset uses itself, such as "input" or "postrouting", is renamed with a trailing underscore. Its rules were merged into that chain and ran on all traffic, and the jump into it made the whole ruleset fail to load, so the firewall kept its old rules.
* Compiler (nftables): a rule set, address table, DNS name or accounting counter whose name happens to be an nftables keyword, such as "log" or "drop", is renamed with a trailing underscore and the rename is reported. Such a name made the whole ruleset fail to load, so the firewall kept its old rules.
* Compiler (nftables): a dual-stack rule for an ICMP service that names no message type stays in the address family it was written for. It applied to IPv6 packets as well, so an IPv4-only ICMP rule acted on both.
* Compiler (nftables): a NAT rule whose translated address cannot be resolved is reported instead of being compiled into a translation of the port alone, which sent the traffic somewhere else than the rule says. A DNS name as the translation target is now refused outright: nftables resolves it while loading and throws away the whole ruleset as soon as the name has a second address.
* Compiler (nftables): a rule listing TCP and UDP services that restrict the source port is compiled into one rule per source port instead of a single rule combining every source with every destination port. The combined rule let through traffic neither service allowed and blocked traffic both did.
* Compiler (nftables): a rule tagging packets with a Tag Service whose value carries a mask sets the same bits as the iptables rule for the same policy. The two platforms cleared different bits, so every rule and every routing decision keyed on that mark could disagree between them.
* Compiler (nftables): a rule whose service list names a whole protocol ("All TCP", "All UDP") next to a specific port covers the whole protocol as well. The unrestricted service was silently swallowed by the port set, so a Deny rule stopped only the port it named and let the rest of the protocol through, unlike the same rule on iptables.
* Compiler (nftables): a rule whose rate limit names its unit the short way, such as "10/sec", produces a ruleset that loads. iptables takes any abbreviation and nftables only the full word, so a policy imported from Firewall Builder compiled on one platform and threw away the whole ruleset on the other, leaving the firewall on its old rules.
* Compiler (nftables): a rate limit kept per source, destination or port forgets a source it has not seen for a while, as the same rule does on iptables. Its table grew with every new address until it was full, and from then on the rule stopped limiting anything new.
* Compiler (nftables): a dual-stack rule with a rate limit kept per source or destination counts IPv4 and IPv6 apart. Both families shared one table, so an IPv6 address was cut to its first four bytes and shared its budget with an unrelated IPv4 address. Two rules that ask one table for different things are now reported instead of producing a ruleset nftables refuses or one that quietly counts something else.
* Compiler (iptables): a rule matching a connection limit or a time of day is left out on a firewall pinned to an iptables release that has no such match, instead of stopping the activation script and leaving every rule after it uninstalled. The connection limit is called differently before 1.2.9, and both matches were missing from 1.3.8 until 1.4.0.
* Compiler (iptables, nftables): a rule whose rate limit keys its counts the way Firewall Builder 2.1 stored it activates. iptables refuses that spelling outright, which stopped the activation script and left every rule after it uninstalled, and nftables silently ignored the key and capped the rule as a whole instead of per address.
* Compiler (nftables): a Reject rule set to send a TCP reset sends one even when the policy spells that reject type the other of its two names. It fell back to an ICMP message with a warning, so the same rule answered differently on the two platforms.
* Compiler (iptables, nftables): a firewall setting whose name is one letter away from a real one is reported, naming the setting it resembles. Such a name was accepted without a word and the compiler used the default instead, so the value never took effect.
* Compiler (iptables, nftables): a management address that is not an address is reported at compile time instead of being written into the backup ssh rule. That rule is installed at the one moment the "Block all traffic" action has already shut every chain, so a value with a space or a shell character in it took away the way back in - and on iptables it would have run whatever it said.
* Compiler (iptables): a dual-stack firewall pinned to an ip6tables older than 1.3.5 leaves out the rules that match on the connection state, with a message, instead of writing commands that release cannot load. It has no such match at all, so the generated script stopped at the first of them with all traffic already blocked. This deliberately differs from what Firewall Builder generated for those firewalls.
* Compiler (iptables, nftables): a NAT rule that redirects to a local port honours its "Random" option instead of dropping it without a word. Both packet filters offer it on that target.
* Compiler (iptables, nftables): a rule assigning a traffic class that is not a tc handle is reported instead of producing a command iptables refuses, which stopped the activation script and left every rule after it uninstalled. nftables takes a bare number there and would have given the same policy a different class.
* Compiler (iptables): a rule marking the connection but saying nothing about what to do with the mark is reported instead of producing a command iptables refuses, and the release gate on that target is no longer skipped on that path.
* Compiler (iptables, nftables): a logging rule whose severity neither tool knows logs at the default severity with a message, instead of producing a command iptables refuses - which stopped the activation script and left every rule after it uninstalled - or an nftables ruleset that fails to load as a whole. The "audit" severity nftables has cannot be combined with a log prefix at all.
* Compiler (iptables): a rate limit or connection limit whose numbers iptables cannot take is reported at compile time instead of stopping the activation script: a rate faster than the match can express, a burst outside its range, a table name the kernel cannot make a name out of, and a connection limit grouping by more bits than the address has. The last one was not even refused for IPv4 - the value was read as a netmask and grouped by something nobody asked for.
* Compiler (iptables): a rule with a rate limit that does not say what it keeps its counts per is left out on a firewall pinned to an iptables older than 1.4.1, with a message. That release was the first to make the key optional; before it the command was refused, which stopped the activation script and left every rule after it uninstalled.
* Compiler (iptables): a rule using the "dstlimit" variant of the rate limit is left out with a message when that match cannot express the key it asks for, instead of producing a command it refuses. The variant knows four fixed combinations, always needs one, and never existed for IPv6.
* Compiler (iptables): a rule with a rate limit that the optimiser splits into a helper chain fires at the rate it names. The limit was applied again inside the chain, and once more for a second level of splitting, so the rule let through a third of what the editor shows.
* Compiler (iptables): two rules whose rate limit names the same table but asks for a different rate or a different key are reported. The kernel keeps the settings of the first rule for both, so the second one was capped at a rate the editor never showed.
* Compiler (nftables): a rule whose rate limit is kept per port but whose service has none, such as an ICMP rule, is still limited. The limit was dropped without a word, so the rule matched every packet; iptables caps such a rule as a whole and nftables now does the same.
* Compiler (nftables): rules that differ only in their destination address are merged again when they also carry a rate limit or a connection limit. The key of such a limit names the same header field and was mistaken for the address the rules are merged on.
* Compiler (nftables): a rule naming two dynamic interfaces, or a dynamic interface next to an address, on the same side is reported instead of being compiled into a rule that asks for a packet whose address is in two places at once, which nothing matches.
* Compiler (nftables): a rule whose rate limit is kept per source port and whose services cover TCP and UDP alike produces a ruleset that loads. Such a rule is compiled into a single rule covering both protocols, and naming one of them in the rate limit made nftables refuse the whole ruleset, so the firewall kept its old rules.
* Compiler (nftables): a rule whose rate limit is kept per source, destination or port matches while the traffic stays below the limit, as the same rule does on iptables. It matched the other way round, so an Accept rule let through only the traffic above the limit and a Deny rule dropped only that - the exact opposite of what the editor shows.
* Compiler (nftables): a rule that lists several ICMP, IP or custom services covers all of them instead of only the first.
* Compiler (nftables): a rule that matches a DNS name resolved on the firewall covers every address the name resolves to instead of making the whole ruleset fail to load.
* Compiler (nftables): a rule that matches the address of a dynamic interface is filled in at activation time instead of being left out, and a rule on a wildcard interface such as "ppp*" covers every interface it matches.
* Compiler (nftables): a rule whose time restriction is negated is reported and left out instead of being compiled without the negation, where it applied at exactly the times it was written to skip.
* Compiler (nftables): a rule that uses a loopback interface without an IP address reports a clear error instead of disappearing silently.
* Compiler (nftables): a rule without an address match applies to the address family it was written for. On a dual-stack firewall such a rule acted on both families, so an IPv4-only "accept" rule let the same traffic through over IPv6 and an IPv6-only one over IPv4.
* Compiler (nftables): an IP service that matches fragmented packets does so instead of letting fragments through.
* Compiler (nftables): a rule that negates an IP service the compiler cannot invert is left out instead of being written the other way round, where it acted on exactly the traffic it was meant to spare.
* Compiler (nftables): an IP service that matches IP options carries that condition instead of matching every packet. The timestamp option, which nftables cannot match, is reported.
* Compiler (nftables): an IP service with protocol "any" no longer restricts the rule to a protocol that matches nothing.
* Compiler (nftables): an IPv6 network with a /0 netmask is reported as a likely mistake, as on iptables.
* Compiler (nftables): dropping TCP sessions that were open before a firewall restart no longer drops legitimate new connections along with them.
* Compiler (nftables): firewalls that log through NFLOG with one of the IP or TCP option logging settings enabled produce a ruleset that loads.
* Compiler (nftables): generated rules carry a counter, so `nft list ruleset` shows per-rule hit counts as the iptables output does.
* Compiler (nftables): a firewall that does not forward packets gets the same automatic rules as on iptables. Its forward chain carried the "drop invalid" and "drop TCP sessions opened prior firewall restart" rules although nothing is forwarded through it.
* Compiler (nftables): an IP service that carries a ToS byte as well as a DiffServ code point is reported, as it is on iptables, instead of quietly matching the DiffServ field. The same service matched a different header field on each platform.
* Compiler (nftables): IP services that match a DSCP value produce a ruleset that loads. A match on the legacy ToS byte, which nftables cannot express, is reported.
* Compiler (nftables): IPv6 NAT rules produce a ruleset that loads.
* Compiler (nftables): logging of invalid packets uses the debug level and the configured NFLOG group. Under a packet flood those messages reached the console.
* Compiler (nftables): long log prefixes are no longer truncated, so log parsers keyed on the full prefix match again.
* Compiler (nftables): NAT rules that match a MAC address where that cannot work drop the match with a warning, as on iptables, instead of translating nothing.
* Compiler (nftables): an address range that covers a single address is treated like that address, so a rule using it lands in the same chain as on iptables. Rules for broadcast traffic ended up in the wrong chains and matched nothing.
* Compiler (nftables): rules that match an address table read on the firewall carry that match, through a named set the activation script fills from the file. Every such rule was left out, so a policy built around a block list did nothing at all.
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
* Test suite: the check that asks the installed iptables which chain names it refuses skips itself on a host that denies unprivileged network namespaces, instead of reporting every name as a failure. Only the test suite is affected.


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
