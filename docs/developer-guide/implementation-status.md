# Implementation status

Every processor documented in the rule processor files is ported and behaves like fwbuilder unless it appears in the lists below. "Not ported" means there is no Python equivalent; "partial" means a Python equivalent exists but has a known behavioral gap. nftables-specific gaps are listed separately under [nftables feature status](rule-processors-nftables.md#nftables-feature-status).

## Not ported

- `createNewCompilerPass` — pass-through bookkeeping, not needed
- `ReplaceFirewallObjectWithSelfInRE` — `"self"` DNSName substitution
- `replaceFailoverInterfaceInRE` — the `pf` variant of the cluster interface
  substitution; `replaceClusterInterfaceInItfRE` is what the two Linux
  pipelines use and it is ported
- `addressRanges` (policy range-to-networks split) — fwf handles `AddressRange` natively via `SpecialCaseAddressRangeIn{Src,Dst}` / `SplitIf{Src,Dst}MatchingAddressRange`
- `SkipActionContinueWithNoLogging` — filter for Continue-with-no-logging rules
- separate shadowing pass: `SplitIfSrcAnyForShadowing` / `SplitIfDstAnyForShadowing` exist but are intentionally left unwired, and the `DetectShadowingForNonTerminatingRules` variant is absent (inline `DetectShadowing` is used instead)

## Partial

- `singleObjectNegation` — the AddressTable/ipset branch aside, the check is
  the C++ one: `single_negation_qualifies` asks the object
  `count_inet_addresses(True) == 1`, which every model class answers for
  itself, and `complex_match` against the firewall.  Only the `shadowing_mode`
  variant of the three chain-building negations is missing (below).
- `SrcNegation` / `DstNegation` / `SrvNegation` — missing the `shadowing_mode` variant; the separate shadowing pass works on copies instead
- `TimeNegation` — nftables inverts one `meta hour`, `meta time` or `meta day`
  with `!=` and needs no chain for it.  Two of them are a disjunction, which
  one nftables rule cannot hold, so an interval naming both a window of the day
  and a set of weekdays — and a rule naming several intervals, whose negation is
  an "and" the atomizing split downstream would turn back into an "or" — is
  expanded into the same jump / return / action chain the iptables processor
  builds for every negated interval.  The nftables compiler has no other
  temporary chain: `PolicyCompiler_nft.get_new_tmp_chain_name` names it,
  declares it in `chain_rules` and records it in `temp_chains`, which is what
  lets `PrintRule_nft._print_verdict` write the jump.
- Calendar window of an `Interval` — the first and last date are compiled as
  `--datestart` / `--datestop` on iptables 1.4.0 and up and as `meta time` on
  nftables, and the daily window is then dropped, the way fwbuilder does it.
  An older iptables has no date options in its time match, so the rule is
  compiled without them and says so; a date outside the 1970-2038 range both
  tools can express is reported and the rule is left out.
- `InterfacePolicyRules` — does not expand a group in the interface rule
  element.  The main pass runs `ExpandGroupsInItf` first, so only the
  shadowing pass, which does not, can meet one.
- "Assume firewall is part of any and networks" is normalised once, in the
  prolog, the way `PolicyCompiler_ipt::prolog` does it: a `.fwb` carries
  the value as ``''``, ``'0'``, ``'1'``, ``'False'``, ``'True'`` or
  ``'true'``, because the option was a checkbox in Firewall Builder 3.0
  and a tri-state afterwards.  Empty and the cleared old checkbox mean
  "use the firewall's setting", the ticked one means on, and anything else
  is read as a number - which is why ``'true'`` is off.  Every processor
  afterwards asks `assumes_fw_is_part_of_any` and nothing else.
- `expandMultipleAddressesInRE` — an interface named in a rule element is
  replaced by every address it carries, its sub-interfaces included, the
  way `Compiler::_expand_addr_recursive` does it.  Three kinds stay in the
  element as objects, because they carry no address the compiler could
  write down and because the checks that report them read the object: a
  dynamic interface, whose addresses the generated script looks up while
  it runs, an unnumbered one, and a bridge port.
- An **Attached Networks** object stands for the subnets of every address
  its parent interface carries and is worked out again on each compile, so
  a rule naming it follows a change of address without being edited.
  Firewall Builder marks it *run time* when that interface is not a
  regular one - dynamic, unnumbered or a bridge port - and then writes
  `$i_<iface>_network` into the rule, a shell variable nothing in its
  generated script sets.  There is nothing to write down at compile time
  for such an interface, so fwf reports the object and leaves the rule
  out.
- `Begin` — leaves out a rule that names a "Dummy" placeholder of the
  Standard library and warns ("Rule contains dummy object and is not
  parsed."), the way `Compiler::Begin` does in fwbuilder 5.  Firewall
  Builder asks this of policy rules only (`PolicyRule::isDummyRule`) and
  compiles the placeholder of a NAT or routing rule as 255.255.255.255;
  fwf leaves those out as well.  A placeholder is recognised by where it
  is - directly in the Standard library - and not by its name
  (`core.objects.placeholder_kind`): Firewall Builder compares fixed ids,
  which fwf regenerates on every load, and a user object called "Any" or
  "Dummy" is an ordinary object.  File > Import Library brings the other
  file's Standard library along as a copy, and
  `redirect_placeholder_copies` points its rules at this file's
  placeholders again.

## Reporting

A message about a rule is recorded once per compiler, not once per copy of
the rule.  This holds for a warning as much as for an error: `Compiler`
overrides `warning()` only to word the message the way the Firewall
Builder output does, and an override that forgets the record or the
`muted()` check turns every internal copy of a rule into another line of
the report.  One rule as the editor shows it reaches the print rule as
several - the service split gives an ICMP and a TCP half a rule each, the
negation expansion builds three, the chain decisions split on top of that -
and repeating one sentence per copy buries the rest of the report.  The
scope is deliberately the compiler and not the driver: the iptables filter
and mangle passes are separate compilers and report separately, because
they compile different rules.  `add_rule_filter()` is what makes that
true, and every pipeline reading the firewall's rules has to start with
it - `run_shadowing_pass()` included, the way
`PolicyCompiler_ipt::compile` calls `addRuleFilter()` in both passes.
A pass that skips it reports the same finding once per table and reasons
about rules its own table never installs.  The inline comments next to
the rules are not de-duplicated, so every emitted copy still carries its
own reason.

A print-rule method that reports something it cannot express answers
`None`, and its caller leaves the rule out.  An empty string is a valid
answer of its own in several of them - `.CONTINUE` carries no target,
a rule that marks nothing carries no mangle statement - which is why the
failure branches cannot use it.  This holds for `_print_target`,
`_print_limit`, `_print_connlimit` and `_print_hashlimit` on iptables and
for `_print_verdict`, `_print_mangle_statement`, `_print_limit` and
`_print_hashlimit` on nftables.

A rule element is rendered out of several objects, and the object that
cannot be rendered is what says why: `_print_addr` names it and its
reason, and the element around it adds a sentence of its own only when
no object gave one - which is the case of an object that carries no
address at all.  Both nftables print rules pass a `reasons` list down
for that.  Two errors about one rule, the second of them the vaguer, is
how a report stops being read.

## Intentional deviations

- `DecideOnChainIfLoopback` — for direction Both, splits into INPUT+OUTPUT rules; C++ sets only one chain. This is deliberate, not a gap.
- Multi-address handling uses `ResolveMultiAddress` (compile-time) + `ProcessMultiAddressObjectsInRE` (runtime) instead of the C++ `swapMultiAddressObjectsInRE`.
- `VerifyPortRanges` (`compiler/processors/_service.py`) and
  `VerifyAddressRanges` (`compiler/processors/_generic.py`) have no C++
  counterpart.  Firewall Builder corrects a range whose end is below its start
  in its editor (`TCPServiceDialog::applyChanges`, its bug #1695481, and
  `AddressRangeDialog::applyChanges`), so its compiler never asks; a data file
  written by an older release, by another tool or by hand carries whatever it
  carries, and both packet filters refuse such a range - iptables the command,
  nftables the whole ruleset.  The same processors bound a port number at
  65535, which is what `xtables_parse_port` does.
- The other `Verify*` processors have no C++ counterpart for the same
  reason: the editor bounds the field and the compiler then trusts it, so a
  data file written elsewhere carries whatever it carries.
  `VerifyIcmpTypes` and `VerifyIpProtocols`
  (`compiler/processors/_service.py`) bound the ICMP type and code and the
  IP protocol number at 255, `VerifyTimeIntervals`
  (`compiler/processors/_generic.py`) the hour and the weekday of an
  Interval, `VerifyMacAddresses` the spelling of a MAC address and
  `VerifyRouteMetrics` (`platforms/linux/_routing_compiler.py`) the metric
  of a route.  All of them are wired into every pipeline that can carry the
  value; a check added late has to be checked against every *other* reader
  of the same field, because a Verify processor only guards what runs after
  it.
- `WarnAnyTCPUDPService` (`compiler/processors/_service.py`) has no C++
  counterpart.  A TCP or UDP service whose ports are all 0 matches every port
  of its protocol, which is how All TCP and All UDP are written, and a new
  service starts out that way, so a forgotten port makes an Accept rule accept
  a whole protocol ([#194](https://github.com/Linuxfabrik/firewallfabrik/issues/194)).
  The processor warns once per rule and service, in the filter pass of both
  policy pipelines, right after the groups are expanded and before any rule is
  split.  The two predefined services are told apart by the library they are
  in (`is_standard_library_object`), not by their name; a Deny or Reject rule,
  a negated element and a service with flags or a port range are not reported.
- `SpecialCasesWithCustomServices` asks whether a Custom Service does its
  own connection-state matching case-insensitively, where the C++ uses a
  case-sensitive `find("ESTABLISHED")`.  Both tools read the state names
  with `strncasecmp` (netfilter `extensions/libxt_conntrack.c` and
  `libxt_state.c`) and nftables knows the lowercase spelling and no other,
  so an administrator may write either - and the two platforms have to
  give one and the same object the same answer.  The predicate is
  `custom_service_matches_state` in `platforms/linux/_netfilter.py`.
- A Branch rule whose target chain can reach the chain the rule is in is
  reported and left out, where Firewall Builder emits the jump and warns.
  The kernel walks every jump reachable from a base chain and answers
  `-EMLINK` at `NFT_JUMP_STACK_SIZE` levels (`nft_chain_validate`,
  netfilter `net/netfilter/nf_tables_api.c`), which both tools report as
  "Too many links" - and neither `nft --check` nor the shell sees it,
  because the ruleset has to reach the kernel first.  nftables loads
  atomically, so the whole ruleset is refused and the firewall keeps the
  rules it had; iptables refuses the jump from every built-in chain and
  installs the rest, so the branch is silently absent from a script that
  activates cleanly.  Only the jump that *closes* the cycle is left out -
  `CompilerDriver.find_branch_loop_edges` walks the branch graph from the
  top rule sets and names the back edges - so the rest of the branch tree
  stays reachable.  This is the one place where `missing` in
  `compare-reference.sh` is one higher than Firewall Builder on purpose.
- A rule set that is not the firewall's own top one names its chains
  after itself even when it is called "Policy".  `getNewChainName` asks
  whether the name is "Policy" and writes `RULE_<n>` when it is, which is
  right for the firewall's own policy and wrong for a rule set of
  *another* firewall that a Branch rule points at - almost every firewall
  object owns one of that name, and `findImportedRuleSets` compiles it
  into this script beside our own.  Both then build `RULE_<n>`, so the
  two rule sets share a chain and whichever rule is appended first
  decides for both; with logging on, the chains form a cycle the kernel
  refuses (`-EMLINK`, "Too many links").  `Compiler.rule_set_key` says
  the same thing for the hashed temporary chain names of the negation
  and SDNAT expansions on both platforms.  This is the second place where
  `missing` in `compare-reference.sh` is higher than Firewall Builder on
  purpose (8 lines, `firewall33-1` and `firewall81`).
- **A rule's rate limit is one bucket for the whole rule.**  Firewall
  Builder writes `-m limit` on every line a rule is compiled into, and a
  `-m limit` or an nftables `limit rate` is a token bucket per line
  (`struct nft_limit` is allocated per expression, `net/netfilter/nft_limit.c`).
  So a rule naming two sources admitted its rate twice - unless a
  temporary chain collected the lines first (`optimize1`, `Logging2`, a
  negation), in which case it admitted it once.  Which of the two an
  administrator got depended on internals the editor does not show, and
  the tooltip says "the rule stops matching".  fwf writes the rule's own
  limit as `-m hashlimit --hashlimit-upto` / `--hashlimit-above` without a
  mode and with a table named after the rule (`limit_rule_<n>`, `m` in
  front in the mangle table), and nftables as a named `limit` object
  (`limit_<rule set>_<n>`, `_v6` for IPv6) that every line references.
  Both keep one bucket per address family, the way iptables keeps one
  hash table per family.  A line that sees the same packets as another
  line of its rule - the CONNMARK save beside the MARK, the classify half
  of a rule that also tags - counts in a bucket of its own
  (`CompRule.limit_instance`), since two buckets seeing one packet stream
  decide alike and one bucket would charge it twice.  The limit of a log
  rule keeps `-m limit` / `limit rate`: it caps each log line.  iptables
  below 1.4.1 has no keyless hashlimit and keeps `-m limit` with a warning.
  The bucket per line, and one bucket per rule with the named table and
  the named object, were measured with nft 0.9.3 to 1.1.6 and iptables
  1.8.4 to 1.8.11 (legacy on Leap 15.5) on Rocky 8 to 10, Debian 11 to
  13, Fedora 44, Leap 15.5 and 16.0 and Ubuntu 22.04 to 26.04.
- **`optimize1` puts the limits on the rule in the temporary chain**, not
  on the jump.  The jump matches on the one element being factored out,
  the service say, so with the limit there a sender the rule does not
  name spent the rule's rate: twenty packets from one left a source the
  rule accepts with none.  The packet still pays once, because only the
  rule in the chain carries the limit.  This and the entry above change
  the iptables output of every rule with a rate limit against the
  Firewall Builder reference.
- **A connection limit narrows a rule, so it never shadows one without.**
  `PolicyCompiler_ipt::checkForShadowingPlatformSpecific` compares
  `connlimit_value` like a rate and checks the keys `connlimit_value_not`
  and `connlimit_suffix`, which no editor writes, so a rule rejecting the
  connections of a source above a limit "shadows" the accept rule below
  it.  `DetectShadowing._connlimits_allow_shadowing` lets a rule with a
  limit shadow only a rule that counts the same way (`connlimit_above_not`,
  `connlimit_masklen`) and matches a subset: a count above a higher limit,
  or a count up to a lower one.  The Firewall Builder iptables reference of
  `test-shadowing-3` reports no shadowing for its connlimit rule set
  either.
- `VerifyScriptLiterals` (`compiler/processors/_generic.py`) asks a
  question none of those do: three objects cannot be resolved by the
  compiler, so their names travel into the generated shell script and are
  read there - the data file of a run-time address table, the name a
  run-time DNS name resolves and the name of a dynamic interface.  A bare
  word is shell syntax and a double-quoted one still expands `$`, a
  backtick and a backslash, so each of them is checked against a positive
  alphabet.  The same processor answers the C++
  `processMultiAddressObjectsInRE` abort for a file name below `%DATADIR%`
  on a firewall that names no data directory.

## Compiling a cluster

A cluster is not a machine: it is what its members have in common.  Both
drivers therefore compile a *member* and are told which cluster it belongs
to, which is what `CompilerDriver::compile` does, and the CLI expands a
cluster named on the command line into one run per member.  Before
anything reads the member's rules,
`CompilerDriver.populate_cluster_elements` gives it what it inherits
(`CompilerDriver::populateClusterElements`):

- the **state sync group**, whose interface names the link conntrackd
  replicates over.  It is remembered on the firewall as
  `state_sync_interface` and `state_sync_group_id` - compile-run values
  that are in no `defaults.yaml` and are read off the options dict rather
  than through `get_option`.
- a **copy of every cluster interface** that has a failover group for this
  member, carrying the address the cluster shares.  The copy is what makes
  that address count as the firewall's, so a rule naming it goes to INPUT
  and OUTPUT and a translation to it resolves to that one address.  It
  shares its name with the member's own interface, which on Linux it has
  to - the failover protocol runs on the member's NIC and the rule says
  `-i <that name>` - so `Interface.cluster_interface` marks it and the
  unique index on (device, interface name) makes an exception for it.
- the cluster's **rule sets**, merged by name: the member's own wins when
  it has rules and is said out loud, an empty one of the same name is
  replaced (`mergeRuleSets`, fwbuilder ticket #372).  All three kinds move
  across - policy, NAT *and* routing, the way `populateClusterElements`
  calls the merge once per type.  The routing one is the easiest to forget
  and the most expensive to lose: no oracle can see it, because
  `compare-reference.sh` counts `$IPTABLES` lines and a route installs
  none, and a member compiled without it activates the new packet filter
  with no route at all.

Everything written there lives in `CompilerDriver.compile_session`, which
is rolled back when the compile ends.  The C++ mutates its object database
because `fwb_ipt` throws it away afterwards; the GUI here compiles in the
same process as the editor.

`platforms/linux/_automatic_rules.py` then builds the rules a member needs
to see the other members - the failover protocol per interface, the state
sync link - and both policy compilers put them in front of the top rule
set with negative positions.  Not ported from `AutomaticRules_ipt`: the
`vrrpd`/`heartbeat` configuration generation, which fwbuilder does not do
for Linux either.

Five more places ask about the cluster next to the firewall, each ported
from its C++ site: `AssignInterface`, `ReplaceFirewallObjectsODst`,
`ReplaceFirewallObjectsTSrc`, `specialCaseWithRedirect` and
`addVirtualAddress` in the NAT pipelines - on a member only the copies of
the cluster interfaces count (fwbuilder ticket #1185) and the interface
facing the destination is looked for on the cluster, which is why the two
are compared by name; `checkForDynamicInterfacesOfOtherObjects` exempts a
dynamic interface of the cluster; `checkInterfaceAgainstAddressFamily`
falls back to the member's own interface (ticket #1172); and
`decideOnChainIfDstFW` puts a rule addressed to a cluster this firewall
belongs to in the input chain, asked from the cluster's own membership so
it holds when the member is compiled on its own.  Every one of them is
skipped where the cluster object is itself what is being compiled - fwf
allows that and Firewall Builder does not.

The generated script must **not** configure the address a failover group
shares: keepalived, heartbeat and corosync put it on and take it off
themselves, so the copy configures nothing and the member's own interface
of that name lists it as "ignore"
(`interfaceProperties::manageIpAddresses`, and `manage_addresses` is
false for every Linux protocol in the resource file).

The values those rules are built from come from the group's options, and
the editor writes them: `gui/cluster_protocol_dialogs.py` behind the
"Edit Parameters" button of the cluster group panel, one dialog per
protocol the way Firewall Builder has one
([#84](https://github.com/Linuxfabrik/firewallfabrik/issues/84)).  Two
of them read differently here.  The port spin boxes start at 1, because
a rule permitting port 0 permits a port nothing speaks, and
`AutomaticRules._group_port` reports a stored value that is no port
rather than writing `--dport 0` the way `atoi` in the C++ does.  And a
group address is read for its family, so an IPv6 sync address produces
an IPv6 object and reaches the IPv6 pass; the C++ checks the text
against both families and then builds an `IPv4` out of it either way,
and the rules disappear.

A cluster group is created under the object it belongs to - a failover
group under the cluster interface, a state sync group under the cluster
([#78](https://github.com/Linuxfabrik/firewallfabrik/issues/78)) - and
carries a protocol from the start, VRRP or conntrack, because a group
with no protocol names none and there are no rules to write for it.  A
Cluster is edited with `ClusterDialog`, the firewall panel without the
iptables release: Firewall Builder writes only `platform` and `host_OS`
onto a cluster and each member compiles for the release it names itself.

## What counts as "the firewall"

`Compiler.complex_match` answers that for every processor that decides a
chain, and it is a port of `ObjectMatcher`, not a comparison of addresses.
Three parts of it are easy to lose:

- Both of its flags default to *on*, the way `Compiler::complexMatch`
  declares them (`Compiler.h:955`), so a broadcast, a multicast and the
  "old broadcast" 0.0.0.0 count as the firewall.  Such a packet is
  delivered locally, can be sent by the firewall itself and is never
  routed, so a rule naming one belongs in INPUT and OUTPUT and never in
  FORWARD.
- The address is compared against every address of the firewall's
  interfaces, so a standalone IPv4 or IPv6 object holding one of them is
  the firewall.  With broadcasts recognised, the network address and the
  broadcast address of each interface's subnet answer too (fwbuilder bug
  #1040773).
- A `Network` object stops at a netmask that is not a host mask.  Whether
  a network the firewall merely has an address on counts is the "assume
  firewall is part of any and networks" question, which the callers ask
  for themselves.

Only `FinalizeChain` and `SplitIf{Src,Dst}MatchingAddressRange` ask with
the flags off, and only on a bridging firewall, which forwards such a
frame instead of terminating it (`b=m= !bridging_fw`).  The same line is
present but commented out in `decideOnChainIf{Src,Dst}FW`, where
`bridgingFw` adds the forward copy afterwards instead.
