# iptables NAT

## iptables NAT Processors

These processors are specific to the iptables NAT compilation pipeline (`NATCompiler_ipt`). They handle interface negation, port translation, NONAT splitting, and address expansion for NAT rules.

### `SingleObjectNegationItfInb` — Transform

Handles single-object negation for the inbound interface (`ItfInb`) element in NAT rules. If the element has negation and contains exactly one object, converts to inline `!` negation by setting `itf_inb_single_object_negation = True` and clearing the negation flag.

> **C++**: `NATCompiler::singleObjectNegationItfInb`

### `SingleObjectNegationItfOutb` — Transform

Mirror of `SingleObjectNegationItfInb` for the outbound interface (`ItfOutb`). Sets `itf_outb_single_object_negation = True` when the element has negation and exactly one object.

> **C++**: `NATCompiler::singleObjectNegationItfOutb`

### `PortTranslationRules` — Transform

Copies ODst into TDst for port-only DNAT rules targeting the firewall. Triggers when `nat_rule_type == DNAT`, TSrc and TDst are both empty, TSrv is set, and ODst is the firewall. This allows `SpecialCaseWithRedirect` to detect and convert it to a Redirect rule downstream.

> **C++**: `NATCompiler_ipt::portTranslationRules`

### `SpecialCaseWithRedirect` — Transform

Converts DNAT rules to Redirect when TDst matches the firewall. After `PortTranslationRules` fills in TDst for port-only translations, this processor reclassifies the rule type to `NATRuleType.Redirect`, which changes the iptables target from `DNAT --to-destination` to `REDIRECT --to-ports`.

> **C++**: `NATCompiler_ipt::specialCaseWithRedirect`

### `SplitNONATRule` — Split

Splits NONAT rules into two: one for `POSTROUTING` and one for `PREROUTING` (or `OUTPUT` if OSrc is the firewall). NONAT rules need ACCEPT in both chains to prevent accidental translation by other rules. When OSrc is the firewall, the second copy goes to OUTPUT with OSrc cleared. A copy is made only for a chain that can match the rule's interfaces - a rule naming an outgoing interface gets no PREROUTING copy - unless no chain can, which `VerifyRules3` then reports. The C++ makes both copies and aborts on the one that cannot match.

> **C++**: `NATCompiler_ipt::splitNONATRule`

### `ReplaceFirewallObjectsODst` — Transform

Replaces Firewall objects in ODst with the firewall's non-loopback Interface objects. Skips Masq and Redirect rule types. This prepares the rule for `ExpandMultipleAddresses` which expands interfaces to their addresses.

> **C++**: `NATCompiler_ipt::ReplaceFirewallObjectsODst`

### `ReplaceFirewallObjectsTSrc` — Transform

Replaces Firewall objects in TSrc with the interface facing ODst. For SNAT rules where TSrc is the firewall itself, finds the interface whose network contains the ODst address and uses that interface's address for the SNAT source. Falls back to all eligible (non-loopback, non-unnumbered, non-bridge-port) interfaces when ODst is "any" or no matching interface is found. When `odst_single_object_negation` is set, skips the direct match and uses the fallback (excluding the ODst-facing interface). Also excludes the OSrc-facing interface from the fallback set.

> **C++**: `NATCompiler_ipt::ReplaceFirewallObjectsTSrc`

### `SingleObjectNegationOSrc` — Transform

Handles single-object negation for OSrc in NAT rules. If OSrc has negation and contains exactly one address object that doesn't `complexMatch()` the firewall, converts to inline `!` negation by setting `osrc_single_object_negation = True` and clearing the negation flag.

> **C++**: `NATCompiler::singleObjectNegationOSrc`

### `SingleObjectNegationODst` — Transform

Mirror of `SingleObjectNegationOSrc` for ODst. Sets `odst_single_object_negation = True` when the element has negation and exactly one address object that doesn't `complexMatch()` the firewall.

> **C++**: `NATCompiler::singleObjectNegationODst`

### `SplitIfOSrcAny` — Split

For DNAT rules where OSrc is "any" (or has `single_object_negation`) and the inbound interface is "any", creates a copy with OSrc set to the firewall object. This is part of the `local_nat` support — when `local_nat` and `firewall_is_part_of_any_and_networks` are both enabled, it ensures locally-originated DNAT traffic gets its own rule. Skips rules added for negation handling.

> **C++**: `NATCompiler_ipt::splitIfOSrcAny`

### `SplitIfOSrcMatchesFw` — Split

Splits rules where OSrc contains the firewall among other objects. Extracts firewall-matching objects into separate rules via `complexMatch()`. The original rule keeps the non-firewall objects.

> **C++**: `NATCompiler_ipt::splitIfOSrcMatchesFw`

### `LocalNATRule` — Transform

For DNAT/DNetnat/Redirect rules where OSrc matches the firewall, sets the chain to OUTPUT. If OSrc is the firewall object itself, clears OSrc to "any" (the OUTPUT chain already implies the firewall is the source).

> **C++**: `NATCompiler_ipt::localNATRule`

### `ExpandMultipleAddresses` (NAT) — Transform

Expands Host/Firewall/Interface objects in NAT element lists (OSrc, ODst, TSrc, TDst) to their Address objects. Expansion scope depends on rule type: NONAT/Return expand OSrc+ODst; SNAT/SDNAT/DNAT expand all four; Redirect expands OSrc+ODst+TSrc. Sorts results by address for deterministic output. Skips loopback interfaces when expanding from Host/Firewall. Lives in `compiler/processors/_generic.py` and is wired into both NAT pipelines.

> **C++**: `NATCompiler::ExpandMultipleAddresses`

### `ClassifyNATRule` (enhanced) — Transform

Enhanced version of the base `ClassifyNATRule` that handles TSrv port translation logic. In addition to classifying by TSrc/TDst presence, it checks whether TSrv translates source ports only, destination ports only, or both (comparing against OSrv to detect no-op translations where ports match). This affects SDNAT detection: `TSrc + dst port translation` or `TDst + src port translation` both classify as SDNAT.

> **C++**: `NATCompiler::classifyNATRule`

---

## iptables NAT pipeline order

The NAT compilation pipeline (`NATCompiler_ipt.compile()`) processes NAT rules
through some 95 processor instances. Read it as the shape of the pass, not as
a ledger: verify the wiring against `compile()` itself, which is where this
listing is derived from.

```
Begin → PrintTotalNumberOfRules →
ExpandGroupsInItfInb → ReplaceClusterInterfaceInItfRE(itf_inb) →
SingleObjectNegationItfInb → ItfInbNegation →
ExpandGroupsInItfOutb → ReplaceClusterInterfaceInItfRE(itf_outb) →
SingleObjectNegationItfOutb → ItfOutbNegation →
ResolveMultiAddress → RecursiveGroupsInRE(osrc/odst/osrv/tsrc/tdst/tsrv) →
EmptyGroupsInRE(osrc/odst/osrv/tsrc/tdst/tsrv) →
ExpandGroups → DropRuleWithEmptyRE → [DropIPv4Rules OR DropIPv6Rules] →
EliminateDuplicatesInOSRC → EliminateDuplicatesInODST → EliminateDuplicatesInOSRV →
NATProcessMultiAddressObjectsInRE(osrc/odst/tsrc/tdst) →
DoOSrvNegation → ConvertToAtomicForOSrv →
ClassifyNATRule → SplitSDNATRule → ClassifyNATRule(reclassify) →
ConvertLoadBalancingRules → VerifyRules →
SingleObjectNegationOSrc → SingleObjectNegationODst →
DoOSrcNegation → DoODstNegation → SplitOnODst →
PortTranslationRules → SpecialCaseWithRedirect →
[SplitIfOSrcAny → SplitIfOSrcMatchesFw (if local_nat)] →
SplitNONATRule → SplitNATBranchRule → LocalNATRule → DecideOnChain → DecideOnTarget →
SplitODstForSNAT → ReplaceFirewallObjectsODst → ReplaceFirewallObjectsTSrc →
SplitOnDynamicInterfaceInODst → SplitOnDynamicInterfaceInTSrc →
ExpandMultipleAddressesInNAT → DropRuleWithEmptyRE →
[DropIPv4Rules OR DropIPv6Rules] → DropRuleWithEmptyRE →
NATSpecialCaseWithUnnumberedInterface →
NATCheckForDynamicInterfacesOfOtherObjects →
VerifyRuleWithMAC → CheckUserServiceInWrongChains →
NATExpandAddressRanges → SplitMultiSrcAndDst →
GroupServicesByProtocol → SeparateTCPWithFlags → VerifyCustomServices →
Verify{PortRanges,IcmpTypes,IpProtocols,AddressRanges,Addresses,MacAddresses,ScriptLiterals} →
VerifyRules2 → SeparatePortRanges → SeparateSrcPort → SeparateSrcAndDstPort →
PrepareForMultiport → SplitMultipleICMP → ConvertToAtomicForAddresses →
AddVirtualAddress → AssignInterface → VerifyRules3 →
DynamicInterfaceInODst → DynamicInterfaceInTSrc → AlwaysUseMasquerade →
ConvertToAtomicForItfInb → ConvertToAtomicForItfOutb →
CheckForObjectsWithErrors → CountChainUsage →
NATPrintRule → SimplePrintProgress
```
