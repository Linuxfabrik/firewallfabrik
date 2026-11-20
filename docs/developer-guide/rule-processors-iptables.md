# iptables Processors

These live in `src/firewallfabrik/platforms/iptables/` and are specific to the iptables/ip6tables backend.

> *C++ reference: `src/iptlib/`*

The compiler object is `PolicyCompiler_ipt` which provides:
- `ipv6` flag — whether compiling for ip6tables
- `my_table` — current table (`filter` or `mangle`)
- `minus_n_commands` — tracks created chains (for deduplication)
- `chain_usage_counter` — tracks per-chain rule counts

## Table filtering

### `dropMangleTableRules` (h:158 / cpp:781) — Filter

Filters rules based on which table is being compiled. When compiling for
**filter** table, drops rules that need mangle (tagging, routing, or
classification with action Continue). When compiling for **mangle** table,
drops rules that don't need mangle. Also drops Branch rules whose target
ruleset only needs the other table.

### `checkActionInMangleTable` (h:164 / cpp:817) — Validation

Aborts if `action == Reject` in the mangle table. The REJECT target is only
valid in the filter table in iptables.

### `checkForUnsupportedCombinationsInMangle` (h:180 / cpp:841) — Validation

Aborts if a mangle table rule combines Route + (Tag or Classify) with a
non-Continue action. This combination is problematic because the first
target (e.g. MARK) jumps to a chain ending with ACCEPT, preventing the
second target (e.g. CLASSIFY) from being reached.

## Action and metadata storage

### `storeAction` (h:211 / cpp:892) — Transform

Preserves original rule metadata before later processors modify it. Stores:

| Stored property | Source |
|----------------|--------|
| `stored_action` | `rule->getActionAsString()` |
| `originated_from_a_rule_with_tagging` | `rule->getTagging()` |
| `originated_from_a_rule_with_classification` | `rule->getClassification()` |
| `originated_from_a_rule_with_routing` | `rule->getRouting()` |

These are read later by chain selection and printing processors.

### `deprecateOptionRoute` (h:187 / cpp:862) — Validation

Aborts if `rule->getRouting()` is true. The ROUTE target was removed from
major Linux distributions and is no longer supported.

## Logging

### `Logging1` (h:235 / cpp:880) — Transform

If the global firewall option `log_all` is true, sets `rule->setLogging(true)`
on every rule. Simple global override.

### `Logging2` (h:241 / cpp:911) — Split

The complex logging processor. When logging is enabled on a rule:

**Case 1**: Action is Continue with no tagging/classification/routing.
- Sets `ipt_target` to `"LOG"` and pushes the rule as-is (the rule itself
  becomes the log rule).

**Case 2**: All other logged rules. Creates up to 3 rules using an
intermediate user-defined chain:

1. **Jump rule**: matches Src/Dst/Srv/Itf, jumps to temp chain. Logging
   and limits are cleared (they apply in the chain, not here).
2. **LOG rule**: in the temp chain, Src/Dst/Srv reset to "any" (already
   matched by the jump), target set to LOG with action Continue.
3. **Action rule**: in the temp chain, Src/Dst reset to "any", carries the
   original action and target. Srv is preserved for `--reject-with tcp-reset`
   which needs the protocol.

### `clearLogInMangle` (h:257 / cpp:570) — Transform

Sets `logging = false` for rules in the mangle table (unless the rule's
ruleset is mangle-only). Prevents duplicate log entries when a rule
generates output in both filter and mangle tables.

## Interface and direction

### `InterfaceAndDirection` (h:417 / cpp:1677) — Transform

Guarantees every rule has valid interface and direction values:

- If direction is undefined, sets it to `Both`.
- If interface is "any" and direction is `Both`, sets the `.iface` property
  to `"nil"` (no `-i` / `-o` option in output).
- If interface is "any" and direction is `Inbound` or `Outbound`, adds a
  wildcard interface `"*"` (becomes `-i +` or `-o +` in output).

### `splitIfIfaceAndDirectionBoth` (h:422 / cpp:1855) — Split

If a rule has a specific interface (not "any") and direction `Both`, splits
it into two rules:
- One with direction `Inbound` (will get `-i iface`).
- One with direction `Outbound` (will get `-o iface`).

Rules with direction already set to Inbound or Outbound pass through.

### `checkInterfaceAgainstAddressFamily` (h:967 / cpp:4198) — Filter

Drops rules whose interface has no addresses matching the current address
family (IPv4 vs. IPv6). For example, an IPv4-only interface in an IPv6
compilation is dropped.

Exceptions (always passed through):
- Dynamic interfaces (address determined at runtime).
- Unnumbered interfaces.
- Bridge port interfaces.
- Failover interfaces — checks the corresponding member interface instead.

## Tag, Classify, Route (mangle table)

### `splitIfTagClassifyOrRoute` (h:246 / cpp:587) — Split

If a rule has more than one of `{tagging, classification, routing}` and
the Src/Dst/Srv/Itf are not all "any", creates an intermediate chain:

1. **Jump rule**: matches all conditions, jumps to the temp chain.
   Logging and limits are cleared.
2. **One rule per option**: in the temp chain, each option gets its own
   rule with action Continue (so control falls through to the next).

This is necessary because each option maps to a different iptables target
(MARK, CLASSIFY, ROUTE), and only one target can be used per rule.

### `clearTagClassifyInFilter` (h:251 / cpp:534) — Transform

When compiling the **filter** table, clears `classification`, `routing`,
and `tagging` flags. These options are only valid in the mangle table.

### `clearActionInTagClassifyIfMangle` (h:264 / cpp:550) — Transform

When in the mangle table and the rule has `tagging` or `classification`,
switches the action to `Continue`. This prevents the rule from terminating
(ACCEPT/DROP) before the mark/classify target can take effect.

### `setChainPreroutingForTag` (h:447 / cpp:1708) — Transform

If the rule has tagging (or `originated_from_a_rule_with_tagging`), no chain
is set yet, direction is Both or Inbound, and interface is "any": sets
`ipt_chain` to `PREROUTING`.

### `setChainPostroutingForTag` (h:452 / cpp:1760) — Transform

Same conditions as above but for direction Both or Outbound: sets
`ipt_chain` to `POSTROUTING`. Used when tagging rules also have routing.

### `setChainForMangle` (h:457 / cpp:1793) — Transform

If in the mangle table and no chain is set:
- Direction `Inbound` → `PREROUTING`
- Direction `Outbound` → `POSTROUTING`
- Direction `Both` → default `FORWARD`, then upgrade to `PREROUTING` based
  on action/direction heuristics.

### `splitIfTagAndConnmark` (h:468 / cpp:1823) — Split

If the action is Tag and the CONNMARK option (`ipt_mark_connections`) is
activated, splits into separate rules: one for MARK and one for CONNMARK
(save/restore). These are different iptables targets that must be separate
rules.

### `checkForRestoreMarkInOutput` (h:462 / cpp:1777) — Transform

If a tagging rule uses CONNMARK and the chain is OUTPUT, sets the
`have_connmark_in_output` flag on the compiler. This flag triggers
generation of a CONNMARK restore-mark rule in the OUTPUT chain during
the `addPredefinedRules` phase.

## Negation

iptables has limited negation support — you can negate a single object with
`!`, but negating a set requires chain-based expansion. The processors
below handle both cases.

### `SingleSrcNegation` / `SingleDstNegation` / `SingleSrvNegation` (h:306-320) — Transform

Handle the optimized case: when a rule element has negation and **exactly
one object**. Sets the `single_object_negation` boolean attribute and
clears the element's negation flag. `PrintRule` later emits a `!` prefix.

Additional checks:
- For `AddressTable` objects with ipset support: always applies (ipset
  supports `! --match-set`).
- For address objects: only applies when the address has exactly one inet
  address and doesn't `complexMatch()` the firewall.
- For `TagService` / `UserService`: always applies.

### `SrcNegation` (h:345 / cpp:1155) — Split

Expands multi-object negation in Src using an intermediate chain. Takes a
`shadowing_mode` constructor parameter.

Creates 3 rules:

1. **Jump rule**: `(any, dst, srv, itf) → temp_chain`. Logging and limits
   cleared (matching happens in original chain, action in temp chain).
2. **RETURN rule**: `(original_src, any, any, any) → RETURN` in temp chain.
   Stateless, no limits. This rule matches traffic that should be
   *excluded* (the negated set) and returns to the calling chain.
3. **Action rule**: moved to temp chain with original action. Src/Dst/Srv
   reset to "any" (already matched). Srv is preserved if action is Reject
   with TCP RST (needs protocol info).

In `shadowing_mode`, Dst/Srv/Interval are preserved in the jump rule
instead of being reset (needed for accurate shadowing comparison).

### `DstNegation` (h:362 / cpp:1285) — Split

Mirror of `SrcNegation` but for the Dst element.

### `SrvNegation` (h:379 / cpp:1421) — Split

Same pattern for the Srv element.

### `TimeNegation` (h:396 / cpp:1537) — Split

Same pattern for the time Interval element.

## Splitting on Src/Dst = any

These processors handle the critical case where `"any"` may or may not
include the firewall itself (controlled by the
`firewall_is_part_of_any_and_networks` option).

### `splitIfSrcAny` (h:485 / cpp:2170) — Split

If Src is "any" (or has `single_object_negation` set) and direction is
not `Inbound`:

1. Creates a copy with `ipt_chain = OUTPUT`, direction = `Outbound`.
   Dst/Srv/Interval are reset to "any" in the copy (these conditions are
   checked in the FORWARD rule).
2. For mangle table with classification: creates an additional copy with
   `ipt_chain = POSTROUTING`.
3. The original rule remains for the FORWARD chain.

Skips if: `firewall_is_part_of_any_and_networks` is false, `has_output_chain`
flag is already set, chain is already assigned, or bridging firewall with
bridge port interfaces (can't use `--physdev-out` in OUTPUT chain).

### `splitIfDstAny` (h:490 / cpp:2255) — Split

Mirror of `splitIfSrcAny` for Dst:

1. Creates a copy with `ipt_chain = INPUT`.
2. For mangle with classification: additional `PREROUTING` copy.
3. Original remains for FORWARD.

### `splitIfSrcAnyForShadowing` / `splitIfDstAnyForShadowing` (h:544-550) — Split

Variants for the shadowing detection pass. Same logic but **don't** reset
Dst/Srv/Interval in the split copies (preserves full match criteria for
accurate shadowing comparison).

## Splitting on firewall matches

### `splitIfSrcMatchesFw` / `splitIfDstMatchesFw` — Split

Inherited from base `splitIfRuleElementMatchesFW`. Splits rules where the
firewall object appears among other objects in Src or Dst. Each occurrence
of the firewall gets its own rule for proper chain assignment.

### `splitIfSrcFWNetwork` (h:569 / cpp:2528) — Split

Splits when Src is a network that the firewall is on. The firewall is a
member of this network, so traffic could be both to/from the firewall and
forwarded. Creates:
- A FORWARD rule (network without the firewall).
- An INPUT rule (firewall only).

### `splitIfDstFWNetwork` (h:575 / cpp:2601) — Split

Mirror for Dst. Creates FORWARD + OUTPUT rules.

### `splitIfSrcNegAndFw` (h:588 / cpp:2011) — Split

Handles the special case where Src has negation AND contains the firewall
AND direction is not Inbound. The firewall must be split out before general
negation expansion:

1. Creates an OUTPUT rule with only the firewall objects in Src.
2. Original rule keeps the non-firewall objects with negation flag preserved.

### `splitIfDstNegAndFw` (h:593 / cpp:2089) — Split

Mirror for Dst with direction not Outbound.

### `splitIfSrcMatchingAddressRange` / `splitIfDstMatchingAddressRange` (h:496-502) — Split

Splits when an AddressRange in Src/Dst includes the firewall's address.
Checks if the range's start/end encompasses any firewall interface address.
If so, splits into OUTPUT/INPUT + FORWARD rules similar to the network case.
The copy is made whatever the other rule element holds, as in Firewall
Builder. An anti-spoofing rule has the firewall as source and may have
an address range as destination; its INPUT copy is the one that drops
the forged packets addressed to the firewall itself
(`tests/test_address_range_fw_split.py`).

## Address range handling

### `specialCaseAddressRangeInSrc` / `specialCaseAddressRangeInDst` (h:518-525) — Transform

If an AddressRange represents a **single address** (`dimension == 1`),
replaces it with a simple IPv4 address object. This avoids the overhead
of `-m iprange` for what's effectively a host match.

## Chain selection

These processors progressively determine the `ipt_chain` property. They
run in a specific order — earlier processors handle special cases, and
`finalizeChain` provides the default.

### `decideOnChainIfSrcFW` (h:734 / cpp:3081) — Transform

If Src matches the firewall (not an AddressRange):
- Direction `Outbound` → chain = `OUTPUT`.
- Direction `Both` → chain = `OUTPUT`, direction changed to `Outbound`.

For bridging firewalls: splits rules where the firewall is on a bridge port
interface, putting the split copy in FORWARD.

### `decideOnChainIfDstFW` (h:740 / cpp:3182) — Transform

If Dst matches the firewall or a cluster member:
- Direction `Inbound` → chain = `INPUT`.
- Direction `Both` → chain = `INPUT`, direction changed to `Inbound`.

### `decideOnChainIfLoopback` (h:764 / cpp:3307) — Transform

For loopback interface with Src = "any" and Dst = "any" and no chain set:
- Direction `Inbound` → chain = `INPUT`.
- Direction `Outbound` → chain = `OUTPUT`.

### `decideOnChainForClassify` (h:769 / cpp:3351) — Transform

If classification is enabled and no chain is set:
- If also tagging: creates a separate rule for tagging without
  classification (action = Continue).
- Sets chain to `POSTROUTING` (CLASSIFY target only works there).

### `finalizeChain` (h:782 / cpp:3384) — Transform

The **last-resort** chain assignment. If no chain has been set:

1. Defaults to `FORWARD`.
2. **Mangle table**: sets `PREROUTING` (inbound) or `POSTROUTING` (outbound).
   Special handling for ACCEPT action based on direction.
3. **Filter table**: checks if Src/Dst matches the firewall to upgrade to
   INPUT/OUTPUT.
4. Drops FORWARD rules if `ip_forward` is disabled on the firewall (warns
   the user).

## Target selection

### `decideOnTarget` (h:787 / cpp:3506) — Transform

Maps the rule's action to an iptables target:

| Rule action | `ipt_target` |
|------------|-------------|
| Accept | `ACCEPT` |
| Deny | `DROP` |
| Reject | `REJECT` |
| Return | `RETURN` |
| Pipe | `QUEUE` |
| Continue | `.CONTINUE` (pseudo-target — no `-j` in output) |
| Custom | `.CUSTOM` |
| Branch | target ruleset name |

For tagging rules: target is set to `MARK`, `CONNMARK`, or `CLASSIFY`
depending on the specific options. For routing: `ROUTE`.

## Firewall object handling

### `removeFW` (h:798 / cpp:3566) — Transform

Strips redundant firewall object references after chain assignment:

- Chain = `INPUT` (or descendant): removes firewall from Dst (redundant —
  INPUT already implies destination is the firewall).
- Chain = `OUTPUT` (or descendant): removes firewall from Src.

Skips if the rule has virtual NAT addresses or upstream negation
(`upstream_rule_neg` flag).

### `specialCaseWithFW1` (h:636 / cpp:2720) — Split

Handles rules where the firewall appears in **both** Src and Dst. Splits
into separate rules so each can be assigned to the correct chain (OUTPUT
for src=fw, INPUT for dst=fw).

### `specialCaseWithFW2` (h:652 / cpp:2853) — Transform

After `specialCaseWithFW1`, expands Src and Dst to interface addresses
**including loopback**. The standard `_expand_addr` skips loopback, but
firewall-to-firewall traffic (e.g. a service listening on localhost) needs it.

### `specialCaseWithFWInDstAndOutbound` (h:645 / cpp:2761) — Filter

Drops a rule with direction Outbound on one of the firewall's interfaces,
outside the OUTPUT chain, whose Dst is the firewall and whose Src is not.
Such a packet goes into INPUT and is never forwarded, so the rule would
never see it. A broadcast or multicast Dst on a bridging firewall, a
negated Src, and - with "assume firewall is part of any and networks"
off - a network object whose mask is not a host mask keep the rule.

## Multi-address and interface expansion

### `expandMultipleAddressesIfNotFWinSrc` / `...Dst` (h:709-710 / cpp:3013-3024) — Transform

Expands multi-address objects (Host, Firewall) in Src/Dst to their
individual interface addresses — **except** if the object is the firewall
itself. The firewall is kept intact so that `removeFW` can strip it later
(expanding would lose the identity needed for chain-based removal).

### `expandLoopbackInterfaceAddress` (h:718 / cpp:3060) — Transform

Replaces loopback interface object references with the actual loopback
address. The standard `_expand_addr` skips loopback to avoid polluting
normal rules, but by this point loopback-specific rules have been isolated
and need the real address.

### `processMultiAddressObjectsInSrc` / `...Dst` (h:619-626) — Split

Splits rules containing `MultiAddress` objects. Each MultiAddress gets its
own rule. This ensures runtime-resolved addresses (DNS names, address tables)
are handled independently.

### `specialCaseWithUnnumberedInterface` (h:672 / cpp:2931) — Transform/Filter

Handles unnumbered interfaces (interfaces with no IP address):

- Direction `Inbound`: drops unnumbered/bridge interfaces from Src.
- Direction `Outbound` in OUTPUT chain: drops from Dst.
- Direction `Outbound` in other chains: drops from Src.

These interfaces can't be matched by address, so address-based rule elements
referencing them are meaningless.

### `checkForDynamicInterfacesOfOtherObjects` (h:681 / cpp:2998) — Validation

For each dynamic interface in Src/Dst, verifies it belongs to the firewall
being compiled (or is a failover interface of the correct cluster). A
dynamic interface of another object can never be resolved: the generated
script asks the host it runs on, which knows only its own interfaces.  The
rule is reported and left out on both platforms and in both pipelines — the
NAT counterpart is `compiler/processors/_generic.py:NATCheckForDynamicInterfacesOfOtherObjects`,
shared by the two NAT compilers.

### `InterfacePolicyRulesWithOptimization` (h:276 / cpp:702) — Split

One rule per interface named in the Itf element, and nothing else: the
name says "with optimization" but the body writes a `subrule_suffix` of
`i1` onto each copy and no chain.  That suffix only reaches
`getNewChainName`, which `Logging2` and `accounting` call earlier in the
pass than this processor runs, so it names nothing — it is dead upstream
as well.  The chain that factors a rule body out is `splitIfTagClassifyOrRoute`,
which is a different processor; earlier notes here conflated the two.

## Reject handling

### `fillActionOnReject` (h:804 / cpp:3668) — Transform

If the rule option `action_on_reject` is empty, copies the default from the
global firewall option. This ensures every Reject rule has an explicit
reject type (e.g. `icmp-port-unreachable`, `tcp-reset`).

### `splitRuleIfSrvAnyActionReject` (h:824 / cpp:3683) — Split

If action is Reject with `--reject-with tcp-reset` and Srv is "any" (or
includes both TCP and non-TCP services):

1. Creates a rule for non-TCP services with `action_on_reject` cleared
   (uses default ICMP unreachable).
2. Creates a rule for TCP services only, preserving the tcp-reset option.

This is necessary because `tcp-reset` only works with TCP protocol.

### `splitServicesIfRejectWithTCPReset` (h:841 / cpp:3755) — Split

More granular version: separates TCP services from other services when
reject-with-tcp-reset is active. Each protocol type gets its own rule
with the appropriate reject method.

## Service handling

### `groupServicesByProtocol` — Split

(Defined in base `Compiler.h`.) Groups services by protocol number so each
output rule has one protocol. This is required because iptables `-p` only
accepts one protocol.

### `separateTCPWithFlags` — Split

Splits TCP services with flags (SYN, ACK, FIN, etc.) into separate rules.
TCP flags require the `-m tcp --tcp-flags` match which can only specify
one flag combination per rule.

### `verifyCustomServices` — Validation

Validates that `CustomService` objects have code for the iptables platform.

### `specialCasesWithCustomServices` (h:867 / cpp:3920) — Transform

Handles known custom services that need special treatment (e.g. services
that set specific match modules or protocols).

### `separatePortRanges` — Split

Separates TCP/UDP services with port ranges that can't be combined in
multiport (e.g. overlapping source/destination ranges).

### `separateUserServices` — Split

Isolates `UserService` objects (iptables `-m owner --uid-owner`) into their
own rules. Only valid in the OUTPUT chain.

### `separateSrcPort` — Split

Splits services with source port specifications. Source and destination
ports need separate match parameters (`--sport` vs `--dport`).

### `prepareForMultiport` (h:921 / cpp:3837) — Split/Transform

Prepares services for the `-m multiport` module:

- **Single service**: passes unchanged.
- **IP/ICMP/Custom services**: each gets its own rule (can't use multiport).
- **≤15 TCP/UDP services**: sets the `ipt_multiport` flag for `PrintRule`.
- **>15 TCP/UDP services**: splits into groups of 15 (multiport limit).

### `checkForStatefulICMP6Rules` (h:855 / cpp:3717) — Validation

If a service is ICMPv6 and the rule is stateful (`stateless == false`),
forces `stateless = true` and issues a warning. ICMPv6 should not be
statefully tracked (it can break IPv6 neighbor discovery).

### `CheckForTCPEstablished` — Validation

Aborts if a TCP service has the "established" flag set. iptables handles
established connections via conntrack, not per-service flags.

## Validation

### `checkMACinOUTPUTChain` (h:811 / cpp:3613) — Validation

iptables cannot match on MAC source address in the OUTPUT chain (packets
haven't been through the network stack yet). Warns and strips MAC
addresses from OUTPUT rules.

### `checkUserServiceInWrongChains` (h:817 / cpp:3645) — Validation

The `-m owner --uid-owner` match only works in the OUTPUT chain (matching
the process that generated the packet). Warns if a UserService appears in
INPUT or FORWARD.

### `SkipActionContinueWithNoLogging` (h:974 / cpp:506) — Filter

Drops rules where `target == .CONTINUE` and there is no logging, tagging,
or classification. Such rules produce no iptables output (no `-j` target
and no `-j LOG`/`-j MARK`/`-j CLASSIFY`), so they are dead code.

## Bridging

### `bridgingFw` (h:429 / cpp:1959) — Transform

For bridging firewalls, ensures broadcast and multicast traffic goes to
the FORWARD chain. Also handles `--physdev` module usage for bridge port
interfaces.

### `convertAnyToNotFWForShadowing` (h:284 / cpp:3973) — Transform

For the shadowing detection pass, when `firewall_is_part_of_any_and_networks`
is true, converts "any" to "!fw" so shadowing analysis correctly accounts
for the firewall being part of "any":

1. Creates a RETURN rule matching the firewall.
2. Modifies the original rule's Src/Dst to be `!fw`.

## Optimization (`PolicyCompiler_ipt_optimizer.cpp`)

### `optimize1` (h:873 / optimizer:152) — Split

Reduces the number of rule element checks by creating sub-chains. Picks
the element with the **fewest objects** (≤15) and splits on it:

1. **Jump rule**: matches only the smallest element, all others set to
   "any", jumps to a temp chain. The rate, connection and per-key limits
   are cleared on it (see [Intentional deviations](implementation-status.md#intentional-deviations)).
2. **Detail rule**: in the temp chain, matches all conditions and carries
   the limits. It is made stateless; the jump keeps the state match.

This is run **3 times** in the pipeline for cascading optimization. Each
pass can split on a different element.

Skips if: any element has ≤1 objects, or 3+ elements are "any" (not enough
to optimize).

### `optimize2` (h:892 / optimizer:259) — Transform

If a rule is a "leaf" (in a user-defined chain, i.e. already filtered by
a jump rule) and the action doesn't need protocol specificity (not Reject
with TCP RST), sets Srv to "any". The protocol was already matched by
the jump rule, so re-checking it is redundant.

### `optimize3` (h:898 / optimizer:290) — Filter

Removes duplicate rules. Converts each rule to its string representation
via `PrintRule`, and drops rules that produce identical output. Uses a
`set<string>` to track seen rules.

### `optimizeForMinusIOPlus` (h:916 / optimizer:317) — Transform

Removes redundant interface matching:
- Chain = INPUT and interface matches all (`+`): removes `-i +` (INPUT
  already implies inbound on all interfaces).
- Chain = OUTPUT and interface matches all: removes `-o +`.

## Accounting

### `accounting` (h:959 / cpp:4111) — Transform

Processes rules with action = Accounting (NFACCT target):

1. Gets accounting chain name from rule option (or generates one).
2. If the accounting chain is the same as the rule's chain: sets target to
   `RETURN`.
3. Otherwise: creates an intermediate accounting chain with a RETURN rule,
   and sets the rule's target to the chain name.

### `countChainUsage` (h:980 / cpp:4173) — Transform

Counts how many rules reference each user-defined chain (via their
`ipt_target`). Stores counts in `compiler->chain_usage_counter`. `PrintRule`
later skips creation of chains with zero usage (dead chains from
optimization or filtering).

## Output generation

### `PrintRule` (h:1068 / PrintRule.cpp:1553) — Output

The final processor. Generates iptables shell commands. For each rule:

1. Checks `chain_usage_counter` — skips if the rule's chain has zero usage.
2. Outputs rule label and comments via `_printRuleLabel()`.
3. Creates chains as needed via `_createChain()` (emits `$IPTABLES -N chain`).
4. Delegates to `OSConfigurator_linux24.print_run_time_wrappers()` for the
   dynamic-interface shell wrapper (`run_time_wrappers` configlet): a
   `for`/`test -n` loop over the address list, or a `getinterfaces` loop for
   a wildcard interface. `NATPrintRule` does the same.
5. Calls `PolicyRuleToString()` to assemble the actual command.

**`PolicyRuleToString()`** assembles the command in this order:

```
$IPTABLES -w -t <table> -A <chain>
    <direction_and_interface>     # -i/-o iface, or -m physdev
    <protocol>                    # -p tcp/udp/icmp/...
    <multiport_module>            # -m multiport (if ipt_multiport)
    <src_addr>                    # -s addr, -m iprange, -m set
    <src_service>                 # --sport port
    <dst_addr>                    # -d addr, -m iprange, -m set
    <dst_service>                 # --dport port, --icmp-type, etc.
    <state_match>                 # -m conntrack --ctstate NEW
    <time_interval>               # -m time --timestart/--timestop
    <modules>                     # -m hashlimit, -m connlimit
    -j <target>                   # ACCEPT/DROP/REJECT/LOG/MARK/chain/etc.
```

Key helper methods:

| Method | Output |
|--------|--------|
| `_printChain()` | Chain name (validated ≤30 chars) |
| `_printDirectionAndInterface()` | `-i`/`-o` for regular interfaces, `-m physdev --physdev-in/out` for bridge ports |
| `_printProtocol()` | `-p tcp -m tcp`, `-p udp -m udp`, `-p icmp -m icmp`, `-p ipv6-icmp` |
| `_printSrcAddr()` / `_printDstAddr()` | `-s`/`-d` addr, or `-m iprange --src/dst-range`, or `-m set --match-set` |
| `_printSrcService()` / `_printDstService()` | `--sport`/`--dport` ports, `--sports`/`--dports` for multiport, `--icmp-type`, `--tcp-flags` |
| `_printTarget()` | `-j TARGET` with options: `--reject-with`, `--set-mark`, `--set-class`, LOG params |
| `_printLogParameters()` | `-j LOG --log-level --log-prefix` or `-j ULOG/NFLOG --nflog-group --nflog-prefix` |
| `_printTimeInterval()` | `-m time --timestart HH:MM --timestop HH:MM --days Mon,Tue,...`, or `--datestart`/`--datestop` for an interval that pins a calendar window (iptables 1.4.0 and up) |
| `_printModules()` | `-m hashlimit --hashlimit-upto N/second --hashlimit-name limit_rule_N` for the rule's rate limit, `-m limit` for a log rule's, `-m connlimit --connlimit-above N`, `-m hashlimit ...` |
| `_printActionOnReject()` | `--reject-with tcp-reset`, `--reject-with icmp-port-unreachable`, etc. |
| `_printRuleLabel()` | Comment block: `# Rule N (label)\n# description\necho "Rule N ..."\n` |
| `_createChain()` | `$IPTABLES -N chainname` (skipped if already created, tracked via `minus_n_commands`) |
| `_printSingleObjectNegation()` | `!` prefix for addresses/interfaces with `single_object_negation` |

### `PrintRuleIptRst` (h:1161 / PrintRuleIptRst.cpp:117) — Output

Variant that generates `iptables-restore` format instead of shell commands.
**Not ported**: the choice is binary in fwf, so restore mode always takes
the echo variant below. The C++ third case — a plain restore stream when
no rule needs a shell variable — has no Python entry point.

### `PrintRuleIptRstEcho` (h:1178 / PrintRuleIptRstEcho.cpp:79) — Output

Variant for `iptables-restore` with echo wrappers, and the only one fwf
selects. Wraps every line in a shell `echo` so a rule can carry a variable
— a run-time address table, a dynamic interface address — which a plain
restore file cannot. The `*filter` / `*nat` and `COMMIT` markers come from
the `script_body_iptables_restore` configlet, not from the printer.
