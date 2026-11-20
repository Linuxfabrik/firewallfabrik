# Processor naming map

C++ rule processor to FirewallFabrik class, in pipeline order. Classes under `compiler/processors/` are shared by both platforms; `platforms/iptables/` and `platforms/nftables/` are platform-specific.

| fwbuilder (C++) | FirewallFabrik (Python) |
|---|---|
| `Begin` | `compiler/processors/_generic.py:Begin` |
| `printTotalNumberOfRules` | `compiler/processors/_generic.py:PrintTotalNumberOfRules` |
| `createNewCompilerPass` | — (not ported) |
| `simplePrintProgress` | `compiler/processors/_generic.py:SimplePrintProgress` |
| `singleRuleFilter` | `compiler/processors/_generic.py:SingleRuleFilter` |
| `Debug` | `compiler/_rule_processor.py:Debug` |
| `dropRuleWithEmptyRE` | `compiler/processors/_generic.py:DropRuleWithEmptyRE` |
| `checkForObjectsWithErrors` | `platforms/iptables/_policy_compiler.py:CheckForObjectsWithErrors` |
| `DropIPv4Rules` | `compiler/processors/_generic.py:DropIPv4Rules` / `DropIPv6Rules` |
| `splitIfRuleElementMatchesFW` | `platforms/iptables/_policy_compiler.py:SplitIfSrcMatchesFw` / `SplitIfDstMatchesFw` |
| `singleObjectNegation` | `platforms/iptables/_policy_compiler.py:SingleSrcNegation` / `SingleDstNegation` |
| `fullInterfaceNegationInRE` | `platforms/iptables/_policy_compiler.py:ItfNegation` + `compiler/processors/_policy.py:ItfNegation` |
| `replaceClusterInterfaceInItfRE` | `compiler/processors/_generic.py:ReplaceClusterInterfaceInItfRE` |
| `eliminateDuplicatesInRE` | `compiler/processors/_generic.py:EliminateDuplicatesInSRC`/`DST`/`SRV` |
| `recursiveGroupsInRE` | `compiler/processors/_generic.py:RecursiveGroupsInRE` |
| `emptyGroupsInRE` | `compiler/processors/_generic.py:EmptyGroupsInRE` |
| `AttachedNetworks::loadFromSource` + `Preprocessor_ipt::convertObject` | `compiler/_compiler.py:Compiler._resolve_attached_networks`, reached through `ResolveMultiAddress` |
| `swapMultiAddressObjectsInRE` | No literal swap-to-runtime processor, but MultiAddress handling is implemented and wired: `compiler/processors/_generic.py:ResolveMultiAddress` resolves compile-time MultiAddress (wired in both pipelines) and `platforms/iptables/_policy_compiler.py:ProcessMultiAddressObjectsInRE` handles runtime `MultiAddressRunTime` objects (wired) |
| `expandMultipleAddressesInRE` | `compiler/_compiler.py:Compiler.expand_addr` method |
| `ReplaceFirewallObjectWithSelfInRE` | — (not ported) |
| `replaceFailoverInterfaceInRE` | — (not ported) |
| `InterfacePolicyRules` | `compiler/processors/_policy.py:InterfacePolicyRules` |
| `ExpandGroups` | `compiler/processors/_generic.py:ExpandGroups` |
| `expandGroupsInSrv` | `platforms/iptables/_policy_compiler.py:ExpandGroupsInSrv` |
| `expandGroupsInItf` | `platforms/iptables/_policy_compiler.py:ExpandGroupsInItf` |
| `ExpandMultipleAddresses` | `compiler/processors/_policy.py` + `platforms/iptables/_policy_compiler.py:ExpandMultipleAddresses` |
| `addressRanges` | — (not ported) |
| `checkForZeroAddr` | `platforms/iptables/_policy_compiler.py:CheckForZeroAddr` |
| `checkForUnnumbered` | `platforms/iptables/_policy_compiler.py:CheckForUnnumbered` |
| `ConvertToAtomicForAddresses` | `compiler/processors/_generic.py:ConvertToAtomicForAddresses` |
| `ConvertToAtomicForIntervals` | `platforms/iptables/_policy_compiler.py:ConvertToAtomicForIntervals` |
| `ConvertToAtomic` | `compiler/processors/_generic.py:ConvertToAtomic` |
| `MACFiltering` | `compiler/processors/_policy.py:MACFiltering` |
| `DetectShadowing` | `compiler/processors/_generic.py:DetectShadowing` |
| `groupServicesByProtocol` | `platforms/iptables/_policy_compiler.py:GroupServicesByProtocol` |
| `separateTCPWithFlags` | `compiler/processors/_service.py:SeparateTCPWithFlags` |
| `separatePortRanges` | `platforms/iptables/_policy_compiler.py:SeparatePortRanges` |
| `separateSrcPort` | `compiler/processors/_service.py:SeparateSrcPort` |
| `separateUserServices` | `compiler/processors/_service.py:SeparateUserServices` |
| `verifyCustomServices` | `compiler/processors/_service.py:VerifyCustomServices` |
| — (FirewallFabrik only) | `compiler/processors/_service.py:VerifyPortRanges` |
| — (FirewallFabrik only) | `compiler/processors/_generic.py:VerifyAddressRanges` |
| — (FirewallFabrik only) | `compiler/processors/_service.py:VerifyIcmpTypes` |
| — (FirewallFabrik only) | `compiler/processors/_service.py:VerifyIpProtocols` |
| — (FirewallFabrik only) | `compiler/processors/_generic.py:VerifyMacAddresses` |
| — (FirewallFabrik only) | `compiler/processors/_generic.py:VerifyScriptLiterals` |
| — (FirewallFabrik only) | `compiler/processors/_generic.py:VerifyTimeIntervals` |
| `CheckForTCPEstablished` | `compiler/processors/_generic.py:CheckForTCPEstablished` |
| `dropMangleTableRules` | `platforms/iptables/_policy_compiler.py:DropMangleTableRules` |
| `checkActionInMangleTable` | `platforms/iptables/_policy_compiler.py:CheckActionInMangleTable` |
| `checkForUnsupportedCombinationsInMangle` | `platforms/iptables/_policy_compiler.py:CheckForUnsupportedCombinationsInMangle` |
| `storeAction` | `platforms/iptables/_policy_compiler.py:StoreAction` |
| `deprecateOptionRoute` | `platforms/iptables/_policy_compiler.py:DeprecateOptionRoute` + `platforms/nftables/_policy_compiler.py:DeprecateOptionRoute` |
| `Logging1` | `platforms/iptables/_policy_compiler.py:Logging1` |
| `Logging2` | `platforms/iptables/_policy_compiler.py:Logging2` |
| `clearLogInMangle` | `platforms/iptables/_policy_compiler.py:ClearLogInMangle` |
| `InterfaceAndDirection` | `platforms/iptables/_policy_compiler.py:InterfaceAndDirection` |
| `splitIfIfaceAndDirectionBoth` | `platforms/iptables/_policy_compiler.py:SplitIfIfaceAndDirectionBoth` |
| `checkInterfaceAgainstAddressFamily` | `platforms/iptables/_policy_compiler.py:CheckInterfaceAgainstAddressFamily` |
| `splitIfTagClassifyOrRoute` | `platforms/iptables/_policy_compiler.py:SplitIfTagClassifyOrRoute` |
| `clearTagClassifyInFilter` | `platforms/iptables/_policy_compiler.py:ClearTagClassifyInFilter` |
| `clearActionInTagClassifyIfMangle` | `platforms/iptables/_policy_compiler.py:ClearActionInTagClassifyIfMangle` |
| `setChainPreroutingForTag` | `platforms/iptables/_policy_compiler.py:SetChainPreroutingForTag` |
| `setChainPostroutingForTag` | `platforms/iptables/_policy_compiler.py:SetChainPostroutingForTag` |
| `setChainForMangle` | `platforms/iptables/_policy_compiler.py:SetChainForMangle` |
| `splitIfTagAndConnmark` | `platforms/iptables/_policy_compiler.py:SplitIfTagAndConnmark` |
| `checkForRestoreMarkInOutput` | `platforms/iptables/_policy_compiler.py:CheckForRestoreMarkInOutput` |
| `SingleSrcNegation` | `platforms/iptables/_policy_compiler.py:SingleSrcNegation` / `SingleDstNegation` / `SingleSrvNegation` |
| `SrcNegation` | `platforms/iptables/_policy_compiler.py:SrcNegation` |
| `DstNegation` | `platforms/iptables/_policy_compiler.py:DstNegation` |
| `SrvNegation` | `platforms/iptables/_policy_compiler.py:SrvNegation` |
| `TimeNegation` | `platforms/iptables/_policy_compiler.py:TimeNegation` + `platforms/nftables/_policy_compiler.py:TimeNegation` |
| `splitIfSrcAny` | `platforms/iptables/_policy_compiler.py:SplitIfSrcAny` |
| `splitIfDstAny` | `platforms/iptables/_policy_compiler.py:SplitIfDstAny` |
| `splitIfSrcAnyForShadowing` | `platforms/iptables/_policy_compiler.py:SplitIfSrcAnyForShadowing` / `SplitIfDstAnyForShadowing` |
| `splitIfSrcMatchesFw` | `platforms/iptables/_policy_compiler.py:SplitIfSrcMatchesFw` / `SplitIfDstMatchesFw` |
| `splitIfSrcFWNetwork` | `platforms/iptables/_policy_compiler.py:SplitIfSrcFWNetwork` |
| `splitIfDstFWNetwork` | `platforms/iptables/_policy_compiler.py:SplitIfDstFWNetwork` |
| `splitIfSrcNegAndFw` | `platforms/iptables/_policy_compiler.py:SplitIfSrcNegAndFw` |
| `splitIfDstNegAndFw` | `platforms/iptables/_policy_compiler.py:SplitIfDstNegAndFw` |
| `splitIfSrcMatchingAddressRange` | `platforms/iptables/_policy_compiler.py:SplitIfSrcMatchingAddressRange` / `SplitIfDstMatchingAddressRange` |
| `specialCaseAddressRangeInSrc` | `compiler/processors/_policy.py:SpecialCaseAddressRangeInSrc` / `SpecialCaseAddressRangeInDst` (shared by both policy pipelines) |
| `decideOnChainIfSrcFW` | `platforms/iptables/_policy_compiler.py:DecideOnChainIfSrcFW` |
| `decideOnChainIfDstFW` | `platforms/iptables/_policy_compiler.py:DecideOnChainIfDstFW` |
| `decideOnChainIfLoopback` | `platforms/iptables/_policy_compiler.py:DecideOnChainIfLoopback` |
| `decideOnChainForClassify` | `platforms/iptables/_policy_compiler.py:DecideOnChainForClassify` |
| `finalizeChain` | `platforms/iptables/_policy_compiler.py:FinalizeChain` |
| `decideOnTarget` | `platforms/iptables/_policy_compiler.py:DecideOnTarget` |
| `removeFW` | `platforms/iptables/_policy_compiler.py:RemoveFW` |
| `specialCaseWithFW1` | `platforms/iptables/_policy_compiler.py:SpecialCaseWithFW1` |
| `specialCaseWithFW2` | `platforms/iptables/_policy_compiler.py:SpecialCaseWithFW2` |
| `specialCaseWithFWInDstAndOutbound` | `platforms/iptables/_policy_compiler.py:SpecialCaseWithFWInDstAndOutbound` |
| `expandMultipleAddressesIfNotFWinSrc` | `compiler/processors/_policy.py:ExpandMultipleAddressesIfNotFWInSrc` / `ExpandMultipleAddressesIfNotFWInDst` |
| `expandLoopbackInterfaceAddress` | `platforms/iptables/_policy_compiler.py:ExpandLoopbackInterfaceAddress` |
| `processMultiAddressObjectsInSrc` | `platforms/iptables/_policy_compiler.py:ProcessMultiAddressObjectsInSrc` / `ProcessMultiAddressObjectsInDst` |
| `specialCaseWithUnnumberedInterface` | `platforms/iptables/_policy_compiler.py:SpecialCaseWithUnnumberedInterface` |
| `checkForDynamicInterfacesOfOtherObjects` | `platforms/iptables/_policy_compiler.py:CheckForDynamicInterfacesOfOtherObjects` |
| `InterfacePolicyRulesWithOptimization` | `platforms/iptables/_policy_compiler.py:InterfacePolicyRulesWithOptimization` |
| `fillActionOnReject` | `platforms/iptables/_policy_compiler.py:FillActionOnReject` |
| `splitRuleIfSrvAnyActionReject` | `platforms/iptables/_policy_compiler.py:SplitRuleIfSrvAnyActionReject` |
| `splitServicesIfRejectWithTCPReset` | `platforms/iptables/_policy_compiler.py:SplitServicesIfRejectWithTCPReset` |
| `groupServicesByProtocol` | `platforms/iptables/_policy_compiler.py:GroupServicesByProtocol` |
| `separateTCPWithFlags` | `compiler/processors/_service.py:SeparateTCPWithFlags` |
| `verifyCustomServices` | `compiler/processors/_service.py:VerifyCustomServices` |
| — (FirewallFabrik only) | `compiler/processors/_service.py:VerifyPortRanges` |
| — (FirewallFabrik only) | `compiler/processors/_generic.py:VerifyAddressRanges` |
| — (FirewallFabrik only) | `compiler/processors/_service.py:VerifyIcmpTypes` |
| — (FirewallFabrik only) | `compiler/processors/_service.py:VerifyIpProtocols` |
| — (FirewallFabrik only) | `compiler/processors/_generic.py:VerifyMacAddresses` |
| — (FirewallFabrik only) | `compiler/processors/_generic.py:VerifyScriptLiterals` |
| — (FirewallFabrik only) | `compiler/processors/_generic.py:VerifyTimeIntervals` |
| — (FirewallFabrik only) | `compiler/processors/_service.py:SplitHelperAssignment` |
| — (FirewallFabrik only) | `compiler/processors/_service.py:WarnAnyTCPUDPService` |
| `specialCasesWithCustomServices` | `platforms/iptables/_policy_compiler.py:SpecialCasesWithCustomServices` |
| `separatePortRanges` | `platforms/iptables/_policy_compiler.py:SeparatePortRanges` |
| `separateUserServices` | `compiler/processors/_service.py:SeparateUserServices` |
| `separateSrcPort` | `compiler/processors/_service.py:SeparateSrcPort` |
| `prepareForMultiport` | `platforms/iptables/_policy_compiler.py:PrepareForMultiport` |
| `checkForStatefulICMP6Rules` | `platforms/iptables/_policy_compiler.py:CheckForStatefulICMP6Rules` |
| `CheckForTCPEstablished` | `compiler/processors/_generic.py:CheckForTCPEstablished` |
| `checkMACinOUTPUTChain` | `platforms/iptables/_policy_compiler.py:CheckMACInOUTPUTChain` |
| `checkUserServiceInWrongChains` | `platforms/iptables/_policy_compiler.py:CheckUserServiceInWrongChains` |
| `SkipActionContinueWithNoLogging` | — (not ported) |
| `bridgingFw` | `platforms/iptables/_policy_compiler.py:BridgingFw` |
| `convertAnyToNotFWForShadowing` | `platforms/iptables/_policy_compiler.py:ConvertAnyToNotFWForShadowing` |
| `optimize1` | `platforms/iptables/_policy_compiler.py:Optimize1` |
| `optimize2` | `platforms/iptables/_policy_compiler.py:Optimize2` |
| `optimize3` | `platforms/iptables/_policy_compiler.py:Optimize3` |
| `optimizeForMinusIOPlus` | `platforms/iptables/_policy_compiler.py:OptimizeForMinusIOPlus` |
| `accounting` | `platforms/iptables/_policy_compiler.py:Accounting` |
| `countChainUsage` | `platforms/iptables/_policy_compiler.py:CountChainUsage` |
| `PrintRule` | `platforms/iptables/_print_rule.py:PrintRule` |
| `PrintRuleIptRst` | not ported (restore mode always takes the echo variant) |
| `PrintRuleIptRstEcho` | `platforms/iptables/_print_rule.py:PrintRuleIptRstEcho` |
| `SingleObjectNegationItfInb` | `platforms/iptables/_nat_compiler.py:SingleObjectNegationItfInb` |
| `SingleObjectNegationItfOutb` | `platforms/iptables/_nat_compiler.py:SingleObjectNegationItfOutb` |
| `PortTranslationRules` | `platforms/iptables/_nat_compiler.py:PortTranslationRules` |
| `SpecialCaseWithRedirect` | `platforms/iptables/_nat_compiler.py:SpecialCaseWithRedirect` |
| `SplitNONATRule` | `platforms/iptables/_nat_compiler.py:SplitNONATRule` |
| `ReplaceFirewallObjectsODst` | `platforms/iptables/_nat_compiler.py:ReplaceFirewallObjectsODst` |
| `ReplaceFirewallObjectsTSrc` | `platforms/iptables/_nat_compiler.py:ReplaceFirewallObjectsTSrc` |
| `SingleObjectNegationOSrc` | `platforms/iptables/_nat_compiler.py:SingleObjectNegationOSrc` |
| `SingleObjectNegationODst` | `platforms/iptables/_nat_compiler.py:SingleObjectNegationODst` |
| `SplitIfOSrcAny` | `platforms/iptables/_nat_compiler.py:SplitIfOSrcAny` |
| `SplitIfOSrcMatchesFw` | `platforms/iptables/_nat_compiler.py:SplitIfOSrcMatchesFw` |
| `LocalNATRule` | `platforms/iptables/_nat_compiler.py:LocalNATRule` |
| `ExpandMultipleAddresses` | `compiler/processors/_generic.py:ExpandMultipleAddressesInNAT` (shared by both NAT pipelines) |
| `NATCompiler_ipt::checkForDynamicInterfacesOfOtherObjects` | `compiler/processors/_generic.py:NATCheckForDynamicInterfacesOfOtherObjects` (shared by both NAT pipelines) |
| `ClassifyNATRule` | `platforms/iptables/_nat_compiler.py:ClassifyNATRule` |

---
