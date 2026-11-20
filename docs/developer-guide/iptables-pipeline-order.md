# Full pipeline order

## C++ reference pipeline (`PolicyCompiler_ipt::compile()`)

> *This is the full C++ pipeline order from `PolicyCompiler_ipt.cpp:4291`. The Python pipeline implements a subset of these processors — see [Implementation status](implementation-status.md) for the current status.*

### Shadowing detection pass (optional)

```
Begin → addRuleFilter → printTotalNumberOfRules → ItfNegation →
InterfacePolicyRules → convertAnyToNotFWForShadowing →
recursiveGroupsInSrc → recursiveGroupsInDst → recursiveGroupsInSrv →
ExpandGroups → dropRuleWithEmptyRE →
eliminateDuplicatesInSRC → eliminateDuplicatesInDST → eliminateDuplicatesInSRV →
swapMultiAddressObjectsInSrc → swapMultiAddressObjectsInDst →
ExpandMultipleAddressesInSrc → ExpandMultipleAddressesInDst → dropRuleWithEmptyRE →
ConvertToAtomic → SkipActionContinueWithNoLogging → checkForObjectsWithErrors →
DetectShadowing → simplePrintProgress
```

This pass converts every rule to fully atomic form (one object per Src/Dst/Srv)
so that `DetectShadowing` can do exact superset comparisons. It uses
`ConvertToAtomic` (the full cartesian product) and `convertAnyToNotFWForShadowing`
to handle the "any includes firewall" case.

### Main compilation pass

```
Begin → addPredefinedRules → addRuleFilter → printTotalNumberOfRules →
singleRuleFilter → deprecateOptionRoute → checkForUnsupportedCombinationsInMangle →
clearTagClassifyInFilter → clearLogInMangle → clearActionInTagClassifyIfMangle →
storeAction → Logging1 →
emptyGroupsInItf → expandGroupsInItf → replaceClusterInterfaceInItf →
singleObjectNegationItf → ItfNegation →
decideOnChainForClassify → InterfaceAndDirection → splitIfIfaceAndDirectionBoth →
recursiveGroupsInSrc → recursiveGroupsInDst → recursiveGroupsInSrv →
emptyGroupsInSrc → emptyGroupsInDst → emptyGroupsInSrv →
SingleSrvNegation → splitRuleIfSrvAnyActionReject → SrvNegation → expandGroupsInSrv →
CheckForTCPEstablished → fillActionOnReject → splitServicesIfRejectWithTCPReset →
fillActionOnReject → splitServicesIfRejectWithTCPReset →
SingleSrcNegation → SingleDstNegation →
splitIfSrcNegAndFw → splitIfDstNegAndFw →
SrcNegation → DstNegation → TimeNegation →
Logging2 → splitIfTagClassifyOrRoute → splitIfTagAndConnmark → Route →
ExpandGroups → dropRuleWithEmptyRE →
eliminateDuplicatesInSRC → eliminateDuplicatesInDST → eliminateDuplicatesInSRV →
swapMultiAddressObjectsInSrc → swapMultiAddressObjectsInDst →
accounting → splitIfSrcAny →
[checkActionInMangleTable if mangle] →
setChainForMangle → setChainPreroutingForTag → splitIfDstAny → setChainPostroutingForTag →
processMultiAddressObjectsInSrc → processMultiAddressObjectsInDst →
[addressRanges OR specialCaseAddressRange* + splitIfMatchingAddressRange*] →
dropRuleWithEmptyRE →
splitIfSrcMatchesFw → splitIfDstMatchesFw →
specialCaseWithFW1 → decideOnChainIfDstFW → splitIfSrcFWNetwork →
decideOnChainIfSrcFW → splitIfDstFWNetwork → specialCaseWithFW2 →
expandMultipleAddressesIfNotFWinSrc → expandMultipleAddressesIfNotFWinDst →
expandLoopbackInterfaceAddress → dropRuleWithEmptyRE →
InterfacePolicyRulesWithOptimization → checkInterfaceAgainstAddressFamily →
decideOnChainIfLoopback → finalizeChain →
specialCaseWithFWInDstAndOutbound → decideOnTarget →
checkForRestoreMarkInOutput → removeFW →
ExpandMultipleAddresses → dropRuleWithEmptyRE →
[DropIPv4Rules OR DropIPv6Rules] →
checkForUnnumbered → checkForDynamicInterfacesOfOtherObjects →
[bridgingFw if bridging] → specialCaseWithUnnumberedInterface →
optimize1 → optimize1 → optimize1 →
groupServicesByProtocol → separateTCPWithFlags → verifyCustomServices →
specialCasesWithCustomServices → separatePortRanges → separateUserServices →
separateSrcPort → checkForStatefulICMP6Rules →
optimize2 → prepareForMultiport →
ConvertToAtomicForAddresses → checkForZeroAddr → checkMACinOUTPUTChain →
checkUserServiceInWrongChains → ConvertToAtomicForIntervals →
optimize3 → optimizeForMinusIOPlus →
checkForObjectsWithErrors → countChainUsage →
PrintRule → simplePrintProgress
```

### Pipeline phases (logical grouping)

The main compilation pass can be understood as these logical phases:

1. **Initialization** — `Begin` through `Logging1`. Injects rules, adds
   predefined rules, stores metadata, applies global logging override.

2. **Interface normalization** — `emptyGroupsInItf` through `ItfNegation`.
   Expands interface groups, replaces cluster interfaces, handles interface
   negation.

3. **Direction splitting** — `decideOnChainForClassify` through
   `splitIfIfaceAndDirectionBoth`. Sets up direction, splits "Both" rules.

4. **Group validation** — `recursiveGroupsIn*` through `emptyGroupsIn*`.
   Checks for recursive and empty groups.

5. **Negation processing** — `SingleSrvNegation` through `TimeNegation`.
   Optimizes single-object negation, splits multi-object negation into
   chains, handles reject/TCP-reset interactions with negation.

6. **Logging and tagging** — `Logging2` through `Route`. Creates LOG rules,
   splits tag/classify/route combinations.

7. **Group expansion** — `ExpandGroups` through `swapMultiAddressObjects*`.
   Expands remaining groups, deduplicates, swaps MultiAddress objects.

8. **Any/firewall splitting** — `accounting` through `setChainPostroutingForTag`.
   Handles "any" includes firewall, creates INPUT/OUTPUT/FORWARD splits.

9. **Address expansion** — `processMultiAddressObjects*` through
   `expandLoopbackInterfaceAddress`. Expands address ranges, multi-address
   objects, handles firewall-network overlaps.

10. **Chain and target assignment** — `InterfacePolicyRulesWithOptimization`
    through `removeFW`. Assigns chains, targets, removes redundant firewall
    references.

11. **Address family filtering** — `ExpandMultipleAddresses` through
    `specialCaseWithUnnumberedInterface`. Final address expansion, drops
    wrong address family, handles unnumbered/dynamic interfaces.

12. **Optimization** — `optimize1` (×3) through `optimizeForMinusIOPlus`.
    Sub-chain optimization, multiport preparation, duplicate removal.

13. **Service normalization** — `groupServicesByProtocol` through
    `checkForStatefulICMP6Rules`. One protocol per rule, separate port
    ranges, validate services.

14. **Final atomization** — `ConvertToAtomicForAddresses` through
    `ConvertToAtomicForIntervals`. One address and one interval per rule.

15. **Output** — `countChainUsage` through `simplePrintProgress`. Count
    chain usage, generate iptables commands, print progress.

### Minimal pipeline (for tracing/development)

This reduced set of 15 processors produces correct output for simple rules:

```
Begin → addRuleFilter → storeAction → InterfaceAndDirection →
ExpandGroups → finalizeChain → decideOnTarget → removeFW →
ExpandMultipleAddresses → groupServicesByProtocol → prepareForMultiport →
ConvertToAtomicForAddresses → countChainUsage → PrintRule → simplePrintProgress
```

## Routing pipeline order

`platforms/linux/_routing_compiler.py`, shared by both platforms — the
routing compiler runs once per firewall, not once per address family.
Ported from `RoutingCompiler_ipt::compile()`; the order is "check what the
rule names, expand it, then check what the expansion left".

```
Begin → PrintTotalNumberOfRules → SingleRuleFilter (auto) →
RecursiveGroupsInRE(rdst) → EmptyGroupsInRE(rdst) →
EmptyRGtwAndRItf → SingleAddressInRGtw → RItfChildOfFw →
VerifyAddressRanges → VerifyRouteMetrics →
ExpandGroups → ExpandMultipleAddressesInRouting → DropRuleWithEmptyRE →
ValidateRoutingDestination → ReachableGateway →
GatewayOnRoutingInterface → ExpandAddressRangesInRDst →
EliminateDuplicatesInRDst → FindDefaultRoute → CompetingRoutingRules →
ConvertToAtomicForRDst → ClassifyRoutingRules →
EliminateDuplicateRoutingRules → NoteIPv6Routes → RoutingPrintRule
```

Two things about that pass are worth knowing before touching it.  Every
check in it compares rule elements **by object id**, the way fwbuilder
does - except `EliminateDuplicateRoutingRules`, which compares what the
command *says*: the destination and the gateway by address and the
interface by name, the way `RoutingRuleToString` renders them.  That is
the whole point of the processor, because two objects holding one address
and two interface objects of one name are one route on the wire.  A
cluster member has exactly that pair, since the copy of a cluster
interface shares its name with the member's own.  And `RItfChildOfFw`
lets an interface of a cluster stand for the firewall's own only when the
firewall is one of *that* cluster's members, asked from the cluster's own
membership so it holds when the member is compiled on its own.

`RoutingPrintRule` writes the `routing_functions` configlet before the
first route command and `RoutingCompilerLinux.epilog()` closes the block
with `restore_script_output`, the way
`RoutingCompiler_ipt::PrintRule::processNext` and its `epilog()` do.  The
configlet saves the routing table the box has, defines
`route_command_error`, and takes the terminal out of the way so a route
that changes the route to the administrator does not leave the session
hanging.  Every command is followed by `|| route_command_error "<label>"`,
or by a warning when the rule carries the `no_fail` option the routing
options dialog writes as "non-critical rule".  `FindDefaultRoute` decides
the configlet's `proto_filter`: with a default route of its own to install
the script may delete the one that is there, without one it has to keep
it.  None of this is emitted in single-rule compile mode, where there are
no shell functions to call.

**The block is written per address family, and that is where this pass
differs from the C++ one.**  `ip route` means the IPv4 table and nothing
else, and Firewall Builder never had to say so because it compiles no
IPv6 route at all.  Here three questions have an answer per table:

* `NoteIPv6Routes` says whether the script installs an IPv6 route, and
  only then does the block save, clear and restore that table beside the
  IPv4 one.  Without it the route survived into the next activation and
  `ip -6 route add` answered "File exists", which stops the script.  It
  sits behind the last processor that can still drop a rule and slurps,
  so it sees the rules the print rule will get and no others - a family
  the script installs no route in must not be touched.
* `FindDefaultRoute` answers `proto_filter` and `proto_filter6`
  separately, or a script installing an IPv6 default route deletes the
  IPv4 default route the box came up with and nothing puts it back.
* `_route_command_key` carries the family, because `route_address`
  writes both `0.0.0.0/0` and `::/0` as `default` - which is what
  `ip route add` wants there - and two default routes out of one device
  are otherwise one key and the second is dropped as a duplicate.

Both readers of the routing table use `ip -o route show`, which puts a
route with several next hops on one line.  Read line by line, `default`
and its indented `nexthop ...` lines are three entries, and the two the
loops build out of the tail are no routes at all: the rollback lost an
equal-cost default route entirely and the delete loop answered each
fragment with an iproute2 usage dump.

Not ported from the C++ pass, and what it costs:

| C++ processor | Consequence |
|---|---|
| `createSortedDstIdsLabel` | Ported as the `_destination_key` helper the two rules below share, not as a processor |
| `checkForObjectsWithErrors` | An object a rule names that failed to load is reported by the policy and NAT passes but not by this one |
| `DropIPv6RulesWithWarning` | Deliberate: fwf compiles an IPv6 route as `$IP -6 route add`, which fwbuilder cannot.  Everything the paragraph above says about the block being written per address family follows from that |

---
