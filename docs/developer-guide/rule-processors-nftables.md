# nftables Processors

These live in `src/firewallfabrik/platforms/nftables/` and are specific to the nftables backend. The nftables compiler is significantly simpler than iptables because nftables has native support for sets (no multiport hack), negation (no temp chains), inline logging (no LOG chain splitting), and user-defined tables/chains.

Key source files:
- `platforms/nftables/_policy_compiler.py` — `PolicyCompiler_nft` and all policy rule processors
- `platforms/nftables/_nat_compiler.py` — `NATCompiler_nft` and all NAT rule processors
- `platforms/nftables/_print_rule.py` — `PrintRule_nft` final output generation (filter rules)
- `platforms/nftables/_nat_print_rule.py` — `NATPrintRule_nft` final output generation (NAT rules)
- `platforms/nftables/_compiler_driver.py` — `CompilerDriver_nft` orchestrator

## Architecture differences from iptables

| Concept | iptables | nftables |
|---------|----------|----------|
| Chain assignment | `-A INPUT` part of each command | Rules written into chain blocks; per-chain `chain_rules` dict |
| Multiport | `-m multiport --dports 22,80,443` (max 15) | Native sets: `tcp dport { 22, 80, 443 }` (unlimited) |
| Negation | Temp chains for multi-object `!` | Native `!=` operator |
| Logging | Separate `-j LOG` rule + temp chain | Inline `log prefix "..." accept` |
| Mangle table | Separate `-t mangle` compilation pass | Separate pass too: a `<name>_mangle` table whose chains hook in at `priority mangle` |
| Address family | Separate `iptables`/`ip6tables` binaries | `inet` family for dual-stack |
| Reject types | `--reject-with icmp-port-unreachable` | `reject with icmp port-unreachable` |
| Incoming interface in postrouting | Refused by the tool (`option_test_and_reject` in `xshared.c`), except as `-m physdev --physdev-in` for a bridge port | `iifname`, which loads and matches |

The last row is a kernel fact with a tool-specific answer, so
`DropRuleWithImpossibleInterface` and `nat_interface_problem` ask the
compiler through `can_match_inbound_in_postrouting()` instead of deciding
for themselves. Since kernel commit `28f8bfd1ac94` ("netfilter: Support iif
matches in POSTROUTING", first in v5.5) the hook is entered with the device
a routed packet came in on. Everything else in that check is unchanged: a
packet has no outgoing device before the routing decision and a locally
generated one no incoming device at all, so `-o`/`oifname` stays impossible
in prerouting and input, and `-i`/`iifname` in output.

## Error reporting

All processors have access to `self.compiler.error(rule, msg)` and `self.compiler.warning(rule, msg)`. Errors appear as inline `# comments` in the generated script, set the compiler status to `FWCOMPILER_ERROR`, and cause the CLI to exit with code 1.

**Convention**: Messages say "not supported in nftables" when the feature genuinely doesn't exist in nftables (e.g. Scrub, Skip actions), and "not yet supported by nftables compiler" when nftables could do it but our compiler doesn't implement it yet (e.g. dynamic interfaces, Branch).

## Policy processors (`platforms/nftables/_policy_compiler.py`)

### `StoreAction` — Transform

Stores the original action string in `rule._extra['stored_action']` before later processors modify it. Used by `PrintRule_nft._get_log_prefix()` for the `%A` macro.

### `InterfaceAndDirection` — Transform

Sets undefined direction to `Both`. If interface is "any" and direction is `Both`, sets `.iface` to `nil` (no `iifname`/`oifname` in output). Otherwise records the interface name.

### `SplitIfIfaceAndDirectionBoth` — Split

Splits rules with a specific interface and direction `Both` into two rules: one `Inbound`, one `Outbound`.

### `FillActionOnReject` — Transform

Copies the default `action_on_reject` from the global firewall option if the rule's own option is empty.

### `Logging_nft` — Transform

Simpler than iptables `Logging2` because nftables supports inline logging.

- **Continue + log** (no tagging/classification/routing): sets `ipt_target = 'LOG'`.
- **Continue + log + tagging/classification/routing**: emits errors for unsupported features, then sets `ipt_target = 'LOG'`.
- **Other action + log**: sets `rule._extra['nft_log'] = True` so `PrintRule_nft` emits `log prefix "..." accept` in a single rule.

Errors reported:
- `Policy routing not yet supported by nftables compiler` — nftables has `fib`+marks, but not implemented.

### `SplitIfSrcNegAndFw` — Split

Splits rules where Src is negated and contains firewall-like objects. Creates an OUTPUT chain rule for the FW objects (keeping negation) and passes through non-FW objects with a `no_output_chain` option. Skips rules that already have a chain assigned or have `Inbound` direction.

### `SplitIfDstNegAndFw` — Split

Mirror of `SplitIfSrcNegAndFw` for Dst. Creates an INPUT chain rule for FW objects (keeping negation) and passes through non-FW objects with a `no_input_chain` option. Skips rules that already have a chain assigned or have `Outbound` direction.

### `NftNegation` — Transform

Converts element negation flags to `single_object_negation` flags for nftables' native `!=` operator. Unlike iptables (which needs temp chains for multi-object negation), nftables supports `!=` for both single and multi-object sets, so this processor simply converts all `src`/`dst`/`srv` negation flags directly — no chain splitting needed.

### `SplitIfSrcAny` / `SplitIfDstAny` — Split

If Src/Dst is "any" (or has `single_object_negation` with a non-firewall object), creates an additional rule for the OUTPUT/INPUT chain. The original remains for FORWARD. First checks the `firewall_is_part_of_any_and_networks` option (per-rule then global) — if not set, passes the rule through unchanged.

### `SplitIfSrcMatchesFw` / `SplitIfDstMatchesFw` — Split

Splits rules where the firewall object appears among other objects in Src/Dst. Each firewall occurrence gets its own rule.

### `DecideOnChainIfDstFW` / `DecideOnChainIfSrcFW` — Transform

Sets chain to `input`/`output` if Dst/Src matches the firewall.

### `SplitIfSrcFWNetwork` / `SplitIfDstFWNetwork` — Split

Splits when Src/Dst contains a network the firewall has an interface on. Creates an additional OUTPUT/INPUT rule.

### `SpecialCaseWithFW2` — Transform

When Src == Dst == firewall, replaces both with the firewall's interface addresses (including loopback).

### `DecideOnChainIfLoopback` — Transform/Split

Assigns `input`/`output` chain for any-any rules on loopback interface. For direction `Both`, splits into two rules.

### `FinalizeChain` — Transform

Last-resort chain assignment. Defaults to `forward`, then upgrades to
`input`/`output` based on direction and firewall match. In the mangle
table the direction decides instead, and an accepting rule goes to
`prerouting` whatever its direction says. A rule that ends up in `forward`
on a firewall whose packet forwarding is off is reported and left out —
both platforms do this, the option is read per address family.

### `DecideOnTarget` — Transform

Maps rule action to iptables-style target string (used internally; `PrintRule_nft` maps to nftables verdicts):

| Action | Target | Notes |
|--------|--------|-------|
| Accept | `ACCEPT` | |
| Deny | `DROP` | |
| Reject | `REJECT` | |
| Return | `RETURN` | |
| Continue | `.CONTINUE` | Pseudo-target — no verdict in output |
| Custom | `.CUSTOM` | The rule's own text, written out verbatim; reported and left out when the firewall names another platform |
| Accounting | `.CONTINUE` | Counts into a named counter, no verdict |
| Branch | target rule set name | A jump into the chain the branch rule set compiles into; a target no chain carries is reported and the rule left out |
| Modify | — | Error: not yet supported by compiler |
| Pipe | `QUEUE` | Rendered as the `queue` verdict |
| Scrub | — | Error: not supported in nftables |
| Skip | — | Error: not supported in nftables |

### `RemoveFW` — Transform

Removes the firewall object from Src (if OUTPUT chain) or Dst (if INPUT chain) after chain assignment.

### `ExpandMultipleAddresses` — Transform

Expands Host/Firewall objects in Src/Dst to their interface addresses via `compiler.expand_addr()`.

### `GroupServicesByProtocol` — Split

Splits rules with services of different protocols. Special case: if only TCP+UDP with identical port sets, merges into `meta l4proto { tcp, udp } th dport ...` by setting `rule._extra['merged_tcp_udp'] = True`.

Within one protocol the rule is split further, because a single nft rule carries one destination port set: TCP/UDP services that agree on their source port stay together, every other service type (ICMP, IP, custom, tag, user) gets its own rule. This is the counterpart of the iptables `PrepareForMultiport`.

### `Optimize3` — Filter

Removes duplicate rules that produce identical nftables commands. Includes the chain name in the dedup key (unlike iptables where the chain is part of the command string).

## NAT processors (`platforms/nftables/_nat_compiler.py`)

### `DropRuleWithEmptyRE` — Filter

Drops rules where `_has_empty_re` is set (a required rule element became empty after upstream processing).

### `EliminateDuplicatesInOSRC` / `EliminateDuplicatesInODST` / `EliminateDuplicatesInOSRV` — Transform

Removes duplicate objects within OSrc/ODst/OSrv by Python object identity.

### `ClassifyNATRule` — Transform

Classifies the NAT rule type based on TSrc/TDst/TSrv contents:

| TSrc | TDst | Type |
|------|------|------|
| any | any | `NONAT` |
| Network | any | `SNetnat` |
| other | any | `SNAT` |
| any | Network | `DNetnat` |
| any | firewall | `Redirect` |
| any | other | `DNAT` |
| set | set | `SDNAT` |
| Branch action | — | `NATBranch` |

A rule may translate nothing but the port, with TSrc and TDst both "any". The translated side then follows from TSrv: a source port makes it an SNAT, a destination port a DNAT, and a port on the side opposite an address translation makes it an SDNAT. Same logic as the iptables `ClassifyNATRule`.

### `SpecialCaseWithRedirect` — Transform

Reclassifies a DNAT rule as `Redirect` when TDst is the firewall. `PortTranslationRules` fills TDst in for a port-only translation that targets the firewall, which is a redirect to a local port rather than a DNAT.

### `VerifyRules` — Validation

Aborts if negation is used in TSrc, TDst, or TSrv (these are not supported in translated elements).

### `DecideOnChain` — Transform

Assigns NAT rules to chains:

| Rule type | Chain |
|-----------|-------|
| SNAT, SNetnat, Masq | `postrouting` |
| DNAT, DNetnat, Redirect | `prerouting` |
| NONAT, Return, SDNAT | no assignment needed |
| Other | Error: no chain assignment |

### `GroupServicesByProtocol` — Split

Splits NAT rules with mixed-protocol services.

### `ConvertToAtomicForAddresses` — Split

Creates the cartesian product of OSrc × ODst × TSrc × TDst. Each output rule has at most one object per element. A negated OSrc / ODst element is kept whole and rendered as `!= { a, b }`, because "not one of these" only holds when none of them matches.

### `AssignInterface` — Transform

Assigns outbound interface for SNAT/Masquerade rules. If TSrc is an interface on the firewall, uses that. Otherwise, creates one rule per non-loopback firewall interface.

## Print rule processors

### `PrintRule_nft` (`platforms/nftables/_print_rule.py`) — Output

Final processor for policy rules. Generates nft rule statements and writes them to the per-chain `compiler.chain_rules` dict.

Rule format: `[iifname/oifname] [ip saddr] [ip daddr] [proto match] [ct state new] [log ...] [verdict]`

Key methods and their error reporting:

| Method | Errors reported |
|--------|----------------|
| `_print_addr(obj, rule)` | Dynamic interface not yet supported by compiler; Interface/Host has no addresses |
| `_print_addr_basic(obj, rule)` | Cannot resolve address for object type |
| `_print_src_addr()` / `_print_dst_addr()` | Could not resolve any source/destination addresses |
| `_print_service()` | Service type not yet supported by compiler |
| `_print_verdict()` | Rule branches to a rule set nftables cannot jump to; rule with a Custom action and no statement; an action with no verdict |
| `_print_reject()` | Unknown reject type, falling back to generic reject (warning) |

Supports:
- Interface matching: `iifname`/`oifname` (wildcard), `iif`/`oif` (loopback — index-based)
- Address matching: CIDR notation, address ranges (`start-end`), sets (`{ addr1, addr2 }`)
- Service matching: TCP/UDP ports (single, range, multiport sets), ICMP type/code, IP protocol number
- IP header matching: fragments (`ip frag-off & 0x1fff != 0`, `frag more-fragments 1`), DSCP, IPv4 options (`ip option lsrr exists`, `ip hdrlength > 5` for "any option")
- Merged TCP+UDP: `meta l4proto { tcp, udp } th dport ...`
- Negation: `!=` on addresses, ports, ICMP type, protocol; the ICMP type/code pair as a concatenation (`icmp type . icmp code != { X . Y }`)
- Connection tracking: `ct state new`
- Inline logging: `log prefix "..." level ...` combined with verdict
- Log prefix macros: `%N` (position), `%A` (action), `%I` (interface), `%C` (chain), `%R` (ruleset)

Reports an error instead of silently dropping a condition it cannot express: a ToS-byte match, the IPv4 timestamp option, a negated custom service, and a negated element whose match consists of several conditions (nftables cannot express the disjunction one rule would need).

### `NATPrintRule_nft` (`platforms/nftables/_nat_print_rule.py`) — Output

Final processor for NAT rules. Generates nft NAT rule statements.

Key methods and their error reporting:

| Method | Errors reported |
|--------|----------------|
| `_print_addr(obj, rule)` | Interface/Host has no addresses; Cannot resolve address for object type |
| `_print_service()` | Service type not yet supported by compiler |
| `_print_nat_action()` | DNAT has no translated destination |

NAT action output:

| Rule type | Output |
|-----------|--------|
| NONAT | `accept` |
| Masq | `masquerade` |
| SNAT/SNetnat | `snat to addr[:port]`, `snat to :port` for a port-only translation |
| DNAT/DNetnat | `dnat to addr[:port]`, `dnat to :port` for a port-only translation |
| Redirect | `redirect [to :port]` |
| Return | `return` |

SDNAT never reaches the print rule: `SplitSDNATRule` splits it into a DNAT
and an SNAT rule beforehand.

## Compiler driver

`CompilerDriver_nft` (`platforms/nftables/_compiler_driver.py`) orchestrates
the full nftables compilation. The overall driver flow and the generated
script structure (a `/bin/sh` script around the ruleset, `table inet
filter { … }`, `table ip nat { … }`) are documented in
[Compilation Pipeline](compilation-pipeline.md). Both iptables and nftables
drivers call `_warn_unsupported_options()` (base `CompilerDriver`) to emit
warnings for recognised but unimplemented firewall options (ULOG/NFLOG,
TCP/IP log options, numeric log levels, log_all, kernel timezone, bridge
interfaces). The nftables driver reuses the iptables routing compiler.

## Policy pipeline order

```
Begin → SingleRuleFilter → DeprecateOptionRoute →
[DropMangleTableRules (filter run) OR KeepMangleTableRules (mangle run)] →
ClearTagClassifyInFilter → ClearActionInTagClassifyIfMangle → ClearLogInMangle →
StoreAction → Logging1 →
EmptyGroupsInRE(itf) → ExpandGroupsInItf → ReplaceClusterInterfaceInItfRE(itf) →
SingleObjectNegationItf → ItfNegation → DecideOnChainForClassify → InterfaceAndDirection → SplitIfIfaceAndDirectionBoth →
ResolveMultiAddress →
RecursiveGroupsInRE(src/dst/srv) → EmptyGroupsInRE(src/dst/srv/itf) →
ExpandGroups → DropRuleWithEmptyRE →
EliminateDuplicatesInSRC/DST/SRV → WarnAnyTCPUDPService →
SplitHelperAssignment →
CheckForTCPEstablished →
SplitRuleIfSrvAnyActionReject → FillActionOnReject → SplitServicesIfRejectWithTCPReset →
FillActionOnReject(2) → SplitServicesIfRejectWithTCPReset(2) →
SrvNegation → AddOtherProtocolsForNegatedService →
Logging_nft → SplitIfTagAndConnmark → Accounting →
SplitIfSrcNegAndFw → SplitIfDstNegAndFw → NftNegation → TimeNegation →
SplitLogWithStatefulLimit →
[DetectShadowing (if check_shading and not single-rule mode)] →
[CheckActionInMangleTable (mangle run)] →
SplitIfSrcAny → SetChainForMangle → SetChainPreroutingForTag → SplitIfDstAny → SetChainPostroutingForTag →
ProcessMultiAddressObjectsInRE(src/dst) →
SpecialCaseAddressRangeInSrc → SpecialCaseAddressRangeInDst →
SplitIfSrcMatchingAddressRange → SplitIfDstMatchingAddressRange →
SplitIfSrcMatchesFw → SplitIfDstMatchesFw → SpecialCaseWithFW1 →
DecideOnChainIfDstFW → SplitIfSrcFWNetwork → DecideOnChainIfSrcFW → SplitIfDstFWNetwork →
SpecialCaseWithFW2 → ExpandMultipleAddressesIfNotFWInSrc → ExpandMultipleAddressesIfNotFWInDst → DropRuleWithEmptyRE →
ConvertToAtomicForInterfaces → CheckInterfaceAgainstAddressFamily →
DecideOnChainIfLoopback → FinalizeChain → SpecialCaseWithFWInDstAndOutbound → DecideOnTarget → CheckForRestoreMarkInOutput →
RemoveFW → ExpandMultipleAddresses → ExpandLoopbackInterfaceAddress → DropRuleWithEmptyRE →
[DropIPv4Rules OR DropIPv6Rules] → DropRuleWithEmptyRE →
CheckForUnnumbered → CheckForDynamicInterfacesOfOtherObjects →
[BridgingFw (if bridging firewall)] →
ConvertToAtomicForIntervals → GroupServicesByProtocol →
VerifyCustomServices →
Verify{PortRanges,IcmpTypes,IpProtocols,AddressRanges,Addresses,MacAddresses,ScriptLiterals,TimeIntervals} →
SpecialCasesWithCustomServices →
CheckForStatefulICMP6Rules →
Optimize3 → CheckMACInOUTPUTChain → CheckUserServiceInWrongChains →
CheckForZeroAddr → CheckForObjectsWithErrors →
PrintRule_nft → SimplePrintProgress
```

Some 110 processor instances vs. some 125 in iptables. The pipeline shares many base processors with iptables (`Begin`, `ExpandGroups`, `DropRuleWithEmptyRE`, `EliminateDuplicatesIn*`, `DropIPv4/6Rules`, `ConvertToAtomicForInterfaces`, `SimplePrintProgress`, `EmptyGroupsInRE`, `DetectShadowing`) but omits the temp-chain and multiport processors (nftables has native `!=` negation and sets).

The same pipeline runs twice per rule set, once per table. `MangleCompiler_nft` (`platforms/nftables/_mangle_compiler.py`) is `PolicyCompiler_nft` with `my_table = 'mangle'`; it swaps the rule filter and reaches the chain names `prerouting` … `postrouting`. `DetectShadowing` runs in the filter pass only — the mangle pass sees a subset of the same rules and would just repeat every warning; in the filter pass it runs right after `TimeNegation`, deliberately before the split-any processors. Negation is handled natively via `!=`: `SplitIfSrcNegAndFw`, `SplitIfDstNegAndFw`, `NftNegation`, plus `TimeNegation`, which still builds a temporary chain and only for the negated interval that says two things at once.  `SrvNegation` builds the same chain for the two service shapes no `!=` can say - a service inspecting TCP flags *and* naming a port, and a match carrying no protocol beside one that does - and `SplitLogWithStatefulLimit` is the third user of that chain.  Everything else about a negated service element is one rule per protocol group, written by `print_negated_services`. `SplitIfSrcAny`/`SplitIfDstAny` check the `firewall_is_part_of_any_and_networks` option with the same improved negation logic as iptables.

## NAT pipeline order

```
Begin →
ExpandGroupsInItfInb → ReplaceClusterInterfaceInItfRE(itf_inb) →
SingleObjectNegationItfInb → ItfInbNegation →
ExpandGroupsInItfOutb → ReplaceClusterInterfaceInItfRE(itf_outb) →
SingleObjectNegationItfOutb → ItfOutbNegation →
ResolveMultiAddress →
RecursiveGroupsInRE(osrc/odst/osrv/tsrc/tdst/tsrv) →
EmptyGroupsInRE(osrc/odst/osrv/tsrc/tdst/tsrv) →
ExpandGroups → DropRuleWithEmptyRE →
[DropIPv4Rules OR DropIPv6Rules] →
EliminateDuplicatesInOSRC/ODST/OSRV →
ClassifyNATRule → SplitSDNATRule → ClassifyNATRule(reclassify) → ConvertLoadBalancingRules → VerifyRules →
SingleObjectNegationOSrc → SingleObjectNegationODst →
NftNegationOSrc → NftNegationODst → AddOtherProtocolsForNegatedServiceInNAT → NftNegationOSrv →
SplitOnODst → PortTranslationRules → SpecialCaseWithRedirect →
[if local_nat: [if fw_part_of_any: SplitIfOSrcAny] → SplitIfOSrcMatchesFw] →
SplitNONATRule → SplitNATBranchRule → LocalNATRule → DecideOnChain → DecideOnTarget →
SplitODstForSNAT → ReplaceFirewallObjectsODst → ReplaceFirewallObjectsTSrc →
ExpandMultipleAddresses → DropRuleWithEmptyRE →
[DropIPv4Rules OR DropIPv6Rules] → DropRuleWithEmptyRE →
NATCheckForDynamicInterfacesOfOtherObjects →
VerifyRuleWithMAC → CheckUserServiceInWrongChains →
GroupServicesByProtocol → SeparateTCPWithFlags → VerifyCustomServices →
Verify{PortRanges,IcmpTypes,IpProtocols,AddressRanges,Addresses,MacAddresses,ScriptLiterals} →
VerifyRules2 → SeparatePortRanges →
SeparateSrcPort → SplitMultipleServices → ConvertToAtomicForAddresses → AssignInterface →
ConvertToAtomicForItfInb → ConvertToAtomicForItfOutb →
CheckForObjectsWithErrors → NATPrintRule_nft → SimplePrintProgress
```

## nftables feature status

Feature coverage of the nftables compiler for the fwbuilder rule model. The
tables split what the compiler already does from what it does not yet do; the
"nftables backend" column notes whether nftables (the technology) can express
the feature at all, independent of our implementation.

### Implemented

| Feature | Notes |
|---------|-------|
| IPv6 dual-stack | Compiled as separate `ip` / `ip6` passes (no unified `inet` table) |
| SDNAT (simultaneous SNAT+DNAT) | `SplitSDNATRule` splits into DNAT+SNAT, handing the translated service to the half it belongs to, then `ClassifyNATRule` reclassifies |
| Port-only NAT | A rule that translates only the port: `Redirect`, `dnat to :port`, `snat to :port` |
| Shadowing detection | `DetectShadowing`, conditional on the `check_shading` option |
| Empty group validation | `EmptyGroupsInRE` in both policy (SRC/DST/SRV/ITF) and NAT (OSRC/ODST/OSRV/TSRC/TDST/TSRV) |
| `firewall_is_part_of_any_and_networks` | Checked by `SplitIfSrcAny` / `SplitIfDstAny` |
| Packet marking (tagging) | `meta mark set` in the mangle table, via `MangleCompiler_nft` |
| Classification | `meta priority set` in the mangle table's postrouting chain |
| Connection marking | `ct mark set mark` per rule, `meta mark set ct mark` prepended to the prerouting and output chains |
| Pipe | `queue`, queue number 0, the same queue the iptables QUEUE target uses |
| Accounting | `counter name "..."` plus a counter object declared in the table |
| Negation expansion (policy) | Native `!=` via `NftNegation` + `SplitIfSrcNegAndFw` / `SplitIfDstNegAndFw`; a negated time that names both a window of the day and a set of weekdays, and a negated service element no single rule can exclude, become a jump / return / action chain, the way iptables says every negated element |
| NAT interface negation | `SingleObjectNegationItfInb` / `SingleObjectNegationItfOutb` + `!=` output |
| NAT OSrc/ODst negation | `SingleObjectNegationOSrc` / `SingleObjectNegationODst` inline `!` flags |
| NAT local_nat | `SplitIfOSrcAny` + `SplitIfOSrcMatchesFw` + `LocalNATRule` |
| NAT ReplaceFirewallObjectsTSrc | Replaces firewall in TSrc with the interface facing ODst |
| Address table (run-time) | A named set per address family, declared with `flags interval` and `auto-merge` in the table its rules are in and filled from the file by `load_address_tables` after the ruleset is loaded.  The script also offers the four commands the iptables script has offered since Firewall Builder wrote them - `reload_address_table`, `add_to_address_table`, `remove_from_address_table` and `test_address_table`, with the same arguments - so a block list can be kept up to date without recompiling the firewall.  They read `address_table_sets`, the index of which set stands for which table, because a table used by both the filter and the NAT rules, or by both address families, has a set for each |
| Custom service whose code nftables has a spelling for | A Custom Service carries one code per platform and no data file written before fwf has an nftables one, so the iptables code is read as a sequence of matches and translated when *every* one of them translates: `-m state --state …` / `-m conntrack --ctstate …` become `ct state …`, `--tcp-flags` and `--syn` become `tcp flags … / …`, `-m owner --uid-owner` / `--gid-owner` become `meta skuid` / `meta skgid` - the match a User Service object already compiles to - a bare `-p` becomes `meta l4proto` where nothing else pins the protocol, and `-m rt` becomes `rt type` / `rt seg-left` / `rt hdrlength` - but only on a service that declares itself IPv6-only, because `rt` in an `ip` table is "cannot use exthdr with ip" and costs the whole ruleset rather than the one rule.  Each mapping is netfilter's own (`state_xlate_print` and `_conntrack3_mt_xlate` in `extensions/libxt_conntrack.c`, `tcp_xlate` in `libxt_tcp.c`, `owner_xlate` in `libxt_owner.c`, `rt_xlate` in `libip6t_rt.c`), SNAT, DNAT and the three RT0 options excepted; a code holding anything else - `-m recent`, `-m string`, `-m psd`, a connection-tracking helper - is left alone and reported, because guessing at platform text is how a rule matches something nobody wrote |

### Partial or not yet implemented

The nftables backend supports all of these; the fwf compiler does not fully
implement them yet. Rules using a "not yet" feature abort with an error; the
"partial" cases work with a warning or in the common case only.

| Feature | nftables backend | fwf status | Notes |
|---------|------------------|-----------|-------|
| Inline logging with verdict | Yes | ✅ | One rule carries the log and the verdict (`log prefix "…" accept`), and the mark or the traffic class beside them where iptables needs a temporary chain for the second target. A log with a rate limit of its own becomes two rules, the way iptables' temporary chain does, so the limit gates the logging and not the traffic — and where the rule *also* holds a limit of its own (a rate limit, a connection limit or a rate limit kept per key), `SplitLogWithStatefulLimit` builds the jump / log / action chain `Logging2` builds, because two lines would consume that limit twice, and a log line without it would log packets the limit then refuses |
| Custom action | any statement | ✅ | The rule's text is appended to the rule the way the iptables printer appends its custom target.  It carries no platform of its own, so the firewall's platform says what it was written in: a firewall naming another one is reported, because nftables refuses the whole ruleset over a statement it cannot parse |
| Branch (sub-policy) | `jump` / `goto` | ⚠️ Partial | Both a policy and a NAT branch rule set get a regular chain and are reached by a `jump`. A NAT branch gets one chain per direction, because prerouting and postrouting are separate hooks. A rule set belonging to another firewall or cluster object is compiled into this script as well, the way `CompilerDriver::findImportedRuleSets` does it.  Two cases stay reported: a branch into the firewall's *own* top rule set, whose chains are hooked and cannot be jumped to - Firewall Builder emits the same empty chain there - and the jump that closes a cycle, which the kernel refuses (`nft_chain_validate` answers `-EMLINK`, "Too many links"); see the note under *Intentional deviations* |
| Dynamic interface addresses | Sets / maps | ✅ | A named set per interface and family, filled by `load_interface_address` from the running interface after the ruleset loads; a wildcard name collects every interface it matches |
| Policy routing | `fib` + marks | ❌ Not yet | `DeprecateOptionRoute` reports the rule and leaves it out, the way the iptables pipeline refuses it ([#125](https://github.com/Linuxfabrik/firewallfabrik/issues/125)) |
