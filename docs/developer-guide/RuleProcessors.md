# Rule Processor Developer Documentation

This document is the per-processor reference. For the surrounding
orchestration (driver, configlets, script assembly, end-to-end flow), see
[Compilation Pipeline](CompilationPipeline.md) first.

The Python implementation follows the same architecture as the original
C++ fwbuilder code. *Legacy C++ source:
`src/libfwbuilder/src/fwcompiler/` (upstream reference).*

---

## Architecture Overview

The compilation pipeline is a chain of `BasicRuleProcessor` objects. Each processor pulls rules from its predecessor via `get_next_rule()`, transforms them, and pushes results into its own `tmp_queue`. Execution is **pull-based**: `run_rule_processors()` calls `process_next()` on the last processor, which recursively pulls from all predecessors.

### Class hierarchy

Python uses the same class hierarchy as the C++ original:

```
BasicRuleProcessor          (_rule_processor.py)
├── PolicyRuleProcessor     (get_next() returns PolicyRule)
├── NATRuleProcessor        (get_next() returns NATRule)
└── RoutingRuleProcessor    (get_next() returns RoutingRule)
```

All concrete processors inherit from one of the typed subclasses and override `process_next()`.

> *C++ historical context: C++ used `DECLARE_POLICY_RULE_PROCESSOR` macros to declare processors. In Python, processors are plain subclasses:*
>
> ```python
> class MyProcessor(PolicyRuleProcessor):
>     def process_next(self) -> bool:
>         rule = self.prev_processor.get_next_rule()
>         ...
> ```

### Core data structures

| Member | Python | Purpose |
|--------|--------|---------|
| `tmp_queue` | `collections.deque` | Output buffer. Processors push transformed rules here. |
| `prev_processor` | `BasicRuleProcessor` | Upstream processor (data source). |
| `compiler` | `Compiler` | Context pointer — gives access to `fw`, `dbcopy`, options, etc. |
| `do_once` | `bool` | Guard for `slurp()` — ensures it only pulls once. |

### Pull-based execution model

The pipeline runs by repeatedly calling `process_next()` on the **last** processor
in the chain. Each processor calls `prev_processor.get_next_rule()` to pull one
rule from upstream:

```
run_rule_processors():
    link each processor to its predecessor
    while (last_processor.process_next()) ;

get_next_rule():
    while (tmp_queue is empty AND process_next() returns true) ;
    if tmp_queue is empty: return None
    else: pop front of tmp_queue and return it

process_next():                    # each processor implements this
    rule = prev_processor.get_next_rule()   # pull one rule
    if rule is None: return False
    ... transform rule ...
    tmp_queue.append(rule)                  # push result(s)
    return True
```

This means a rule only flows through the chain when the final processor
demands it — processors that drop a rule simply don't push to `tmp_queue`,
and splitting processors push multiple rules for one input.

#### The `slurp()` method

Some processors need the entire rule set at once (e.g. `DetectShadowing`,
`PrintTotalNumberOfRules`). They call `slurp()` instead of `get_next_rule()`:

```python
def slurp(self) -> bool:
    if not self.do_once:
        while (rule := self.prev_processor.get_next_rule()) is not None:
            self.tmp_queue.append(rule)
        self.do_once = True
        return len(self.tmp_queue) != 0
    return False  # subsequent calls return False immediately
```

After slurping, the processor can iterate `tmp_queue` freely. On the next
call from `get_next_rule()`, the buffered rules drain out one at a time.

### Processor categories

- **Source** — injects rules into the pipeline (`Begin`)
- **Splitting** — one input rule produces multiple output rules (e.g. expand groups, atomize, negation expansion)
- **Filtering** — rules may be dropped (e.g. drop empty rule elements, drop wrong address family)
- **Transforming** — rules are modified in place (e.g. set chain, set target)
- **Validation** — rules are checked for errors (may abort compilation)
- **Pass-through** — rule passes unchanged; side effects only (e.g. print progress, count rules)
- **Output** — rules are converted to platform-specific text

### Key rule properties (iptables)

Processors communicate through string properties stored on the Rule object:

| Property | Set by | Read by | Values |
|----------|--------|---------|--------|
| `ipt_chain` | `finalizeChain`, `decideOnChain*`, `setChain*` | `PrintRule`, `countChainUsage`, `removeFW` | `INPUT`, `OUTPUT`, `FORWARD`, `PREROUTING`, `POSTROUTING`, user-defined chain name |
| `ipt_target` | `decideOnTarget` | `PrintRule`, `countChainUsage` | `ACCEPT`, `DROP`, `REJECT`, `RETURN`, `QUEUE`, `.CONTINUE`, `.CUSTOM`, chain name |
| `stored_action` | `storeAction` | `PrintRule` | Original action string before later processors modify it |
| `originated_from_a_rule_with_tagging` | `storeAction` | `splitIfSrcAny`, chain processors | `true` if original rule had tagging |
| `originated_from_a_rule_with_classification` | `storeAction` | chain processors | `true` if original rule had classification |
| `originated_from_a_rule_with_routing` | `storeAction` | chain processors | `true` if original rule had routing |
| `single_object_negation` | `SingleSrc/Dst/SrvNegation` | `PrintRule` | `true` — use `!` prefix instead of chain-based negation |
| `ipt_multiport` | `prepareForMultiport` | `PrintRule` | `true` — use `-m multiport` module |
| `action_on_reject` | `fillActionOnReject` | `PrintRule` | `tcp-reset`, ICMP unreachable type, etc. |

---

## Base Processors (platform-independent)

These live in `src/firewallfabrik/compiler/processors/` and are reusable by all compiler backends.

> *C++ reference: `src/libfwbuilder/src/fwcompiler/`*

### Compiler utilities

#### `Begin` (line 310 / 733) — Source

Injects rules from `source_ruleset` into the pipeline. On first call, iterates
the source ruleset and for each rule:

1. Skips disabled rules and dummy rules (with warning).
2. Creates a **copy** in `compiler->dbcopy` and adds it to `compiler->temp_ruleset`.
3. Pushes the copy to `tmp_queue`.
4. Sets `init = true` and returns `true`.

On subsequent calls returns `false` immediately. All downstream processors
work with these copies, not the originals.

> **Python**: ✅ `compiler/processors/_generic.py:Begin` — matches C++

#### `printTotalNumberOfRules` (line 323 / 764) — Pass-through

Calls `slurp()` to buffer all upstream rules. If verbose mode is on, prints
" processing N rules". Returns `true` once (rules then drain from buffer),
`false` if no rules.

> **Python**: ⚠️ `compiler/processors/_generic.py:PrintTotalNumberOfRules` — slurps correctly but never prints the "processing N rules" message, no verbose check (not wired into pipeline)

#### `createNewCompilerPass` (line 337 / 780) — Pass-through

Takes a `pass_name` constructor parameter. Calls `slurp()`, prints the pass
name, and returns `true`. Creates a logical boundary between compilation
phases — all rules are buffered and then re-released.

> **Python**: ❌ Not implemented

#### `simplePrintProgress` (line 349 / 838) — Pass-through

Pulls one rule at a time. If the rule's label differs from the previous one,
prints " rule LABEL" (when verbose). Pushes the rule unchanged.

> **Python**: ⚠️ `compiler/processors/_generic.py:SimplePrintProgress` — just passes rules through; no `current_rule_label` tracking, no " rule LABEL" output

#### `singleRuleFilter` (line 631 / 818) — Filter

Used in single-rule compilation mode (`-xp`). Pulls each rule and checks:
- If not in `single_rule_mode`: pushes rule through unchanged.
- If in `single_rule_mode`: only pushes rules whose ruleset name matches
  `single_rule_ruleset_name` AND whose position matches `single_rule_position`.
  Other rules are silently dropped.

Always returns `true` (even when dropping) to keep pulling upstream.

> **Python**: ✅ `compiler/processors/_generic.py:SingleRuleFilter` — matches C++ (not wired into pipeline)

#### `Debug` (line 621 / 791) — Pass-through

Calls `slurp()` to buffer all upstream rules. When `rule_debug_on` is true,
prints a separator line with the **previous** processor's name, then for each
rule matching `debug_rule`, calls `debugPrintRule()`. Automatically inserted
after every processor by `Compiler::add()` when `-xp` is active (except after
`simplePrintProgress`).

> **Python**: ✅ `compiler/_rule_processor.py:Debug` — matches C++. Uses `slurp()`, prints separator with previous processor name, calls `compiler.debug_print_rule()` for matching rules. Automatically inserted by `Compiler.add()` when `rule_debug_on` is True (except after `SimplePrintProgress`). `PolicyCompiler_ipt` overrides `debug_print_rule()` with rich columnar output matching C++. Activated via CLI `--xp N`/`--xn N`/`--xr N`.

#### `dropRuleWithEmptyRE` (line 562 / 1564) — Filter

Pulls one rule and checks for empty (non-"any") rule elements:
- **PolicyRule**: checks Src, Dst.
- **NATRule**: checks OSrc, ODst, OSrv, TSrc, TDst, TSrv.
- **RoutingRule**: checks RDst, RGtw, RItf.

If any required element is empty (was non-empty before upstream processing
removed objects), the rule is **dropped** with an optional warning. Otherwise
pushes through.

This processor appears multiple times in the pipeline — after each stage that
can remove objects from rule elements (group expansion, address family
filtering, address expansion, etc.).

> **Python**: ✅ `compiler/processors/_generic.py:DropRuleWithEmptyRE` — checks `has_empty_re` flag set by upstream processors that remove objects from elements. Used in both policy and NAT pipelines.

#### `checkForObjectsWithErrors` (line 594 / 1411) — Validation

Pulls one rule and iterates all rule elements. For each object that has a
`.rule_error` attribute set to `true`, calls `compiler->abort()` with the
object's `.error_msg`. This propagates errors from MultiAddress objects that
failed DNS resolution or other preprocessor steps.

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:CheckForObjectsWithErrors` — matches C++

#### `DropIPv4Rules` / `DropIPv6Rules` (line 534 / 545) — Filter

Both inherit from `DropRulesByAddressFamilyAndServiceType`. For each rule
element:

1. Removes addresses of the unwanted family via `DropAddressFamilyInRE()`.
2. Removes services incompatible with the family via `DropByServiceTypeInRE()`
   (checks `isV4Only()` / `isV6Only()` on each service).
3. If a rule element that was non-empty becomes empty, drops the entire rule
   with a warning.

`DropIPv4Rules` removes IPv4 (for IPv6-only compilation);
`DropIPv6Rules` removes IPv6 (for IPv4-only compilation).

> **Python**: ✅ `compiler/processors/_generic.py:DropIPv4Rules` / `DropIPv6Rules` — matches C++

### Generic rule element processors

These are **parameterized** — they take a slot name (e.g. `'src'`) and operate on that specific rule element. Named convenience subclasses instantiate them for specific elements (see [Convenience subclasses](#compiler-level-convenience-subclasses)).

> *C++ reference: `Compiler.h` / `Compiler.cpp`*

#### `splitIfRuleElementMatchesFW` (line 363 / 861) — Split

Splits rules that contain the firewall object in a specified rule element.
For each object in the element that matches the firewall (by ID,
`parent_cluster_id`, or `complexMatch()`):

1. Creates a **new rule** with only that matching object in the element.
2. Pushes the new rule to `tmp_queue`.

After extracting all matches, removes them from the **original** rule's
element and pushes the original too. This ensures the firewall gets its own
rule for proper chain assignment (OUTPUT for firewall-sourced, INPUT for
firewall-destined, FORWARD for others).

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:_SplitIfRuleElementMatchesFW` — matches C++ (via `SplitIfSrcMatchesFw` / `SplitIfDstMatchesFw`)

#### `singleObjectNegation` (line 376 / 985) — Transform

Optimizes negation when a rule element has `getNeg() == true` and exactly
one object. Instead of the expensive chain-based negation expansion, sets
the `single_object_negation` boolean attribute on the rule and clears the
negation flag. This lets `PrintRule` emit a simple `!` prefix.

For interface elements (`Itf`, `ItfInb`, `ItfOutb`): always applies.

For address elements: only applies when the single address has exactly one
inet address AND doesn't `complexMatch()` the firewall (which would need
splitting first).

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:SingleSrcNegation` / `SingleDstNegation` — marks `single_object_negation` if neg+size==1, with `isinstance(Address)` type check and `complexMatch(fw)` guard. Wired into pipeline. Missing: no `countInetAddresses` check (relies on `isinstance(Address)` which excludes Host/Firewall/Interface), no AddressTable/ipset handling, no TagService/UserService special case

#### `fullInterfaceNegationInRE` (line 389 / 1036) — Transform

Expands a negated interface element into the explicit set of all *other*
interfaces. Given "not eth0, eth1":

1. Gets all firewall interfaces.
2. Filters out: unprotected interfaces, loopback, bridge ports (unless
   `bridging_fw`), cluster interfaces.
3. Removes the negated interfaces from the remaining set.
4. Replaces the rule element contents with the remaining interfaces.
5. Clears the negation flag.

Result: `!{eth0, eth1}` becomes `{eth2, eth3}`.

> **Python**: ⚠️ `platforms/iptables/_policy_compiler.py:ItfNegation` + `compiler/processors/_policy.py:ItfNegation` — two implementations. ipt version: single-object case correctly marks `single_object_negation`; multi-object case replaces with all other interfaces but only excludes loopback — missing C++ filters for unprotected, bridge port, and cluster interfaces (not wired into pipeline)

#### `replaceClusterInterfaceInItfRE` (line 402 / 1102) — Transform

For each interface in the rule element that belongs to a failover cluster:

1. Looks up the `FailoverClusterGroup`.
2. Calls `getInterfaceForMemberFirewall()` to find the real member interface.
3. Replaces the cluster interface reference with the real interface.
4. Sorts the element by name for deterministic output.

Must run **before** `ItfNegation` (which needs real interfaces).

> **Python**: ❌ Not implemented

#### `eliminateDuplicatesInRE` (line 434 / 1148) — Transform

Removes duplicate objects within a rule element. Iterates through the
element, keeping only the first occurrence of each object (compared by ID
via the `equalObj` functor, or a custom comparator). If duplicates were
removed, clears and rebuilds the element with unique objects only.

> **Python**: ✅ `compiler/processors/_generic.py:EliminateDuplicatesInSRC`/`DST`/`SRV` — deduplication by object identity

#### `recursiveGroupsInRE` (line 450 / 1204) — Validation

For each group object in the rule element, recursively checks all children
for circular references (a group containing itself, directly or indirectly).
Aborts compilation with an error if recursion is detected.

> **Python**: ❌ Not implemented

#### `emptyGroupsInRE` (line 470 / 1258) — Filter/Transform

Detects groups with zero non-group children (recursively counted via
`countChildren()`). Behavior depends on the `ignore_empty_groups` firewall
option:

- **If true**: removes the empty groups and issues a warning. If the rule
  element becomes "any" after removal, **drops the entire rule** with a
  warning (a match-nothing element is meaningless).
- **If false**: aborts compilation with an error listing the empty groups.

> **Python**: ✅ `compiler/processors/_generic.py:EmptyGroupsInRE` — parameterized by slot name. Recursively counts group children via `expand_group()`. Respects `ignore_empty_groups` option: removes empty groups with warning (or aborts). Drops rule if element becomes "any" after removal. Wired into both iptables and nftables policy pipelines (SRC, DST, SRV, ITF) and iptables NAT pipeline (OSRC, ODST, OSRV, TSRC, TDST, TSRV).

#### `swapMultiAddressObjectsInRE` (line 486 / 1340) — Transform

Replaces compile-time `MultiAddress` objects (where `isRunTime() == true`)
with their `MultiAddressRunTime` equivalents. Generates a stable ID by
appending `"_runtime"` to the original object's string ID. Looks up or
creates the runtime object in `dbcopy`. This allows platform-specific
handling of DNS names and other dynamic address types.

> **Python**: ❌ Not implemented

#### `expandMultipleAddressesInRE` (line 499 / 1401) — Transform

Replaces Host and Firewall objects in a rule element with their individual
interface addresses. Calls `compiler->_expand_addr()` which:

1. Recursively expands address objects via `_expand_addr_recursive()`.
2. Skips loopback interfaces (unless the rule is attached to loopback).
3. Skips bridge ports.
4. Expands failover cluster interfaces to corresponding member interfaces.
5. Filters by current address family (IPv4 vs. IPv6).
6. Sorts results by address value for deterministic output.

> **Python**: ✅ `compiler/_compiler.py:Compiler.expand_addr` method — used by `ExpandMultipleAddresses`

#### `ReplaceFirewallObjectWithSelfInRE` (line 858 / 915) — Transform

Replaces explicit firewall object references with a `DNSName` object named
`"self"` (source name `"self"`). This is used by platforms that support
runtime self-identification. Looks up or creates the runtime DNSName in
`dbcopy`. Should run after `splitIfSrc/DstMatchesFw` to ensure the firewall
is isolated in its own rule.

> **Python**: ❌ Not implemented

#### `replaceFailoverInterfaceInRE` (line 606 / 1440) — Transform

Replaces cluster failover interfaces with real member interfaces. Handles
both interfaces where `isFailoverInterface() == true` and those with the
`cluster_interface` option set. For each, looks up the `FailoverClusterGroup`
and gets the corresponding member interface via
`getInterfaceForMemberFirewall()`.

> **Python**: ❌ Not implemented

### PolicyCompiler processors

> *C++ reference: `PolicyCompiler.h` / `PolicyCompiler.cpp`*

#### `InterfacePolicyRules` (line 152 / 358) — Split

Associates rules with interfaces. If the Itf element is "any", pushes the
rule unchanged. Otherwise, for each object in Itf:

- If the object is an `ObjectGroup`: iterates its members, creating one rule
  per interface (validates each is actually an `Interface`).
- If the object is an individual `Interface`: creates one rule with only
  that interface.

Each output rule has exactly one interface in its Itf element.

> **Python**: ✅ `compiler/processors/_policy.py:InterfacePolicyRules` — matches C++ (not wired into pipeline; ipt uses `ConvertToAtomicForInterfaces` instead)

#### `ExpandGroups` (line 160 / 414) — Transform

Recursively expands all group objects in **Src, Dst, and Srv**. Calls
`compiler->expandGroupsInRuleElement()` for each, which:

1. Recursively replaces group references with their member objects.
2. Skips `MultiAddressRunTime` objects (already handled).
3. Checks address family compatibility.
4. Sorts results alphabetically by name.
5. Validates each expanded object is appropriate for the element type.

> **Python**: ✅ `compiler/processors/_generic.py:ExpandGroups` — matches C++

#### `expandGroupsInSrv` (line 165 / 431) — Transform

Same as `ExpandGroups` but only for the **Srv** element.

> **Python**: ❌ Not implemented (`ExpandGroups` does all three)

#### `expandGroupsInItf` (line 170 / 440) — Transform

Same as `ExpandGroups` but only for the **Itf** element.

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:ExpandGroupsInItf` — correct, calls `expand_groups_in_rule_element()` on Itf only (not wired into pipeline)

#### `ExpandMultipleAddresses` (line 277) — Transform

Expands Host and Firewall objects in both **Src and Dst** to their
individual interface addresses. Calls `compiler->_expand_addr()` on each.

> **Python**: ✅ `compiler/processors/_policy.py` + `platforms/iptables/_policy_compiler.py:ExpandMultipleAddresses` — matches C++

#### `addressRanges` (line 283 / 472) — Split

Expands `AddressRange` objects in Src and Dst to equivalent network objects:

- **IPv4 ranges**: converted to a set of networks via `convertAddressRange()`.
- **IPv6 ranges**: kept as-is (iptables supports `-m iprange` for IPv6).

Creates `Network` objects for each converted address and registers them
with `group_registry` if present.

> **Python**: ❌ Not implemented

#### `checkForZeroAddr` (line 407 / 673) — Validation

Detects likely configuration errors:

1. `findHostWithNoInterfaces()` — finds Host objects with no Interface children
   (can't have an address).
2. `findZeroAddress()` — finds Address/Network/Host with address 0.0.0.0.
   Skips the "any" object, dynamic interfaces, unnumbered interfaces, and
   bridge ports. Also catches the pattern A.B.C.D/0 where A.B.C.D ≠ 0.0.0.0
   (likely a /32 vs. /0 typo).

Aborts compilation if any are found.

> **Python**: ❌ Not implemented

#### `checkForUnnumbered` (line 299 / 718) — Validation

Calls `compiler->catchUnnumberedIfaceInRE()` on Src and Dst. Aborts if any
interface is unnumbered or a bridge port (these can't be used as addresses
in rules).

> **Python**: ❌ Not implemented

#### `ConvertToAtomicForAddresses` (line 310 / 733) — Split

Creates the **cartesian product** of Src × Dst. For each (src_obj, dst_obj)
pair, creates a new rule with exactly one object in Src and one in Dst.
Srv is left unchanged (may still have multiple objects).

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:ConvertToAtomicForAddresses` — matches C++ (Src × Dst cartesian product)

#### `ConvertToAtomicForIntervals` (line 316 / 762) — Split

Splits rules so each has exactly one `Interval` object. If the Interval
element is "any" or missing, pushes the rule unchanged. Otherwise creates
one rule per interval.

> **Python**: ❌ Not implemented

#### `ConvertToAtomic` (line 321 / 790) — Split

Full atomic conversion: creates the **cartesian product** of Src × Dst × Srv.
Each output rule has exactly one object in each element. Used in the
shadowing detection pass where exact comparison is needed.

> **Python**: ✅ `compiler/processors/_generic.py:ConvertToAtomic` — matches C++ (not wired into pipeline; only used by shadowing pass)

#### `MACFiltering` (line 509 / 980) — Transform

Removes `physAddress` objects from Src and Dst (MAC filtering is unsupported
on most platforms). Issues a warning if any were removed. Aborts if a rule
element becomes empty after removal (means the rule only matched on MAC).

> **Python**: ✅ `compiler/processors/_policy.py:MACFiltering` — matches C++ (not wired into pipeline)

#### `DetectShadowing` (line 449 / 891) — Validation

Uses `slurp()` to load the entire ruleset. For each rule (skipping fallback
and hidden rules):

1. Calls `find_more_general_rule()` to check all previously seen rules.
2. If a more general rule is found (and they have different absolute rule
   numbers and aren't identical), aborts with an error showing which rule
   shadows which.
3. Adds the current rule to `rules_seen_so_far`.

Also has a variant `DetectShadowingForNonTerminatingRules` that detects
when a non-terminating rule (Continue) shadows a terminating rule above it.

> **Python**: ✅ `compiler/processors/_generic.py:DetectShadowing` — fully implemented. Processes rules one at a time (no slurp), accumulates in `_rules_seen`. Skips rules with negation, Branch/Continue/Return/Accounting actions, fallback, or hidden flags. Checks interface, direction, chain, and all three elements (src, dst, srv) for containment. Address containment via `_addr_contains()` supports Network, AddressRange, and single Address. Service containment via `_srv_contains()` supports TCP/UDP port range, ICMP type, IPService flags/proto, and cross-type IPService(proto=0) shadowing. Wired into both iptables and nftables policy pipelines (conditional on `check_shading` option). Missing: `DetectShadowingForNonTerminatingRules` variant, separate shadowing pass with `ConvertToAtomic` + `convertAnyToNotFWForShadowing`.

### Generic service processors

These processors operate on the Srv (or OSrv for NAT) rule element.

> *C++ reference: `Compiler.h` / `Compiler.cpp`*

#### `groupServicesByProtocol` (line 655) — Split

Inherits from `groupServices`, which splits rules with multiple services into
groups based on a virtual `groupingCode()`. For `groupServicesByProtocol`,
the grouping code is `srv->getProtocolNumber()`. Result: each output rule
has services of the same protocol.

If the rule has only one service, it passes through unchanged.

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:GroupServicesByProtocol` — matches C++

#### `separateTCPWithFlags` — Split

Inherits from `separateServiceObject`. Separates TCP services that have TCP
flags set into individual rules. Condition: `TCPService::isA(srv) && has flags`.

> **Python**: ❌ Not implemented

#### `separatePortRanges` — Split

Separates TCP/UDP services where source and destination port ranges are
mismatched (can't be combined in a single `-m multiport` match).

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:SeparatePortRanges` — matches C++

#### `separateSrcPort` — Split

Separates TCP/UDP services that have source port specifications into
individual rules (source ports need separate `--sport` matches).

> **Python**: ❌ Not implemented

#### `separateUserServices` — Split

Separates `UserService` objects (iptables `--uid-owner` match) into
individual rules (only valid in OUTPUT chain).

> **Python**: ❌ Not implemented

#### `verifyCustomServices` — Validation

For each `CustomService` in the Srv element, checks that
`getCodeForPlatform(compiler->myPlatformName())` is non-empty. Throws
`FWException` if a custom service has no code for the target platform.

> **Python**: ❌ Not implemented

#### `CheckForTCPEstablished` — Validation

Aborts if any `TCPService` in Srv has `getEstablished() == true` (the
"established" flag is not supported by the iptables platform — stateful
matching is done via conntrack instead).

> **Python**: ❌ Not implemented

### Compiler-level convenience subclasses

Many generic processors are instantiated as named subclasses for specific
rule elements. These are defined in the Compiler and PolicyCompiler headers:

| Subclass | Base processor | Rule element | Python |
|----------|---------------|--------------|--------|
| `eliminateDuplicatesInSRC` | `eliminateDuplicatesInRE` | Src | ✅ `compiler/processors/_generic.py` |
| `eliminateDuplicatesInDST` | `eliminateDuplicatesInRE` | Dst | ✅ `compiler/processors/_generic.py` |
| `eliminateDuplicatesInSRV` | `eliminateDuplicatesInRE` | Srv | ✅ `compiler/processors/_generic.py` |
| `recursiveGroupsInSrc` | `recursiveGroupsInRE` | Src | ❌ |
| `recursiveGroupsInDst` | `recursiveGroupsInRE` | Dst | ❌ |
| `recursiveGroupsInSrv` | `recursiveGroupsInRE` | Srv | ❌ |
| `emptyGroupsInSrc` | `emptyGroupsInRE` | Src | ✅ `compiler/processors/_generic.py:EmptyGroupsInRE('...', 'src')` |
| `emptyGroupsInDst` | `emptyGroupsInRE` | Dst | ✅ `compiler/processors/_generic.py:EmptyGroupsInRE('...', 'dst')` |
| `emptyGroupsInSrv` | `emptyGroupsInRE` | Srv | ✅ `compiler/processors/_generic.py:EmptyGroupsInRE('...', 'srv')` |
| `emptyGroupsInItf` | `emptyGroupsInRE` | Itf | ✅ `compiler/processors/_generic.py:EmptyGroupsInRE('...', 'itf')` |
| `swapMultiAddressObjectsInSrc` | `swapMultiAddressObjectsInRE` | Src | ❌ |
| `swapMultiAddressObjectsInDst` | `swapMultiAddressObjectsInRE` | Dst | ❌ |
| `ExpandMultipleAddressesInSrc` | `expandMultipleAddressesInRE` | Src | ❌ (single `ExpandMultipleAddresses` does both) |
| `ExpandMultipleAddressesInDst` | `expandMultipleAddressesInRE` | Dst | ❌ (single `ExpandMultipleAddresses` does both) |
| `splitIfSrcMatchesFw` | `splitIfRuleElementMatchesFW` | Src | ✅ `platforms/iptables/_policy_compiler.py` |
| `splitIfDstMatchesFw` | `splitIfRuleElementMatchesFW` | Dst | ✅ `platforms/iptables/_policy_compiler.py` |
| `singleObjectNegationItf` | `singleObjectNegation` | Itf | ❌ (`ItfNegation` handles single-object inline) |
| `ItfNegation` | `fullInterfaceNegationInRE` | Itf | ⚠️ `platforms/iptables/_policy_compiler.py` (see above) |
| `replaceClusterInterfaceInItf` | `replaceClusterInterfaceInItfRE` | Itf | ❌ |

### Common implementation patterns

These patterns recur throughout the processor implementations:

#### Pattern 1: Safe iteration with deferred modification

```python
# Collect objects to remove first, then modify (avoids mutation during iteration)
to_remove = [obj for obj in rule.src if condition(obj)]
for obj in to_remove:
    rule.src.remove(obj)
```

#### Pattern 2: Creating duplicate rules (splitting)

```python
new_rule = rule.duplicate()
new_rule.src = [object]         # set single object
self.tmp_queue.append(new_rule)
```

#### Pattern 3: Accessing typed objects in rule elements

```python
for obj in rule.src:
    if isinstance(obj, Address):
        # process address
        ...
```

> *C++ reference: The C++ equivalents use `FWReference::getObject()`, `RuleElement::cast()`, and `Rule::duplicate()` with explicit memory management.*

---

## iptables Processors

These live in `src/firewallfabrik/platforms/iptables/` and are specific to the iptables/ip6tables backend.

> *C++ reference: `src/iptlib/`*

The compiler object is `PolicyCompiler_ipt` which provides:
- `ipv6` flag — whether compiling for ip6tables
- `my_table` — current table (`filter` or `mangle`)
- `minus_n_commands` — tracks created chains (for deduplication)
- `chain_usage_counter` — tracks per-chain rule counts

### Table filtering

#### `dropMangleTableRules` (h:158 / cpp:781) — Filter

Filters rules based on which table is being compiled. When compiling for
**filter** table, drops rules that need mangle (tagging, routing, or
classification with action Continue). When compiling for **mangle** table,
drops rules that don't need mangle. Also drops Branch rules whose target
ruleset only needs the other table.

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:DropMangleTableRules` — matches C++

#### `checkActionInMangleTable` (h:164 / cpp:817) — Validation

Aborts if `action == Reject` in the mangle table. The REJECT target is only
valid in the filter table in iptables.

> **Python**: ❌ Not implemented

#### `checkForUnsupportedCombinationsInMangle` (h:180 / cpp:841) — Validation

Aborts if a mangle table rule combines Route + (Tag or Classify) with a
non-Continue action. This combination is problematic because the first
target (e.g. MARK) jumps to a chain ending with ACCEPT, preventing the
second target (e.g. CLASSIFY) from being reached.

> **Python**: ❌ Not implemented

### Action and metadata storage

#### `storeAction` (h:211 / cpp:892) — Transform

Preserves original rule metadata before later processors modify it. Stores:

| Stored property | Source |
|----------------|--------|
| `stored_action` | `rule->getActionAsString()` |
| `originated_from_a_rule_with_tagging` | `rule->getTagging()` |
| `originated_from_a_rule_with_classification` | `rule->getClassification()` |
| `originated_from_a_rule_with_routing` | `rule->getRouting()` |

These are read later by chain selection and printing processors.

> **Python**: ⚠️ `platforms/iptables/_policy_compiler.py:StoreAction` — stores `stored_action` only. Missing: `originated_from_a_rule_with_tagging`, `originated_from_a_rule_with_classification`, `originated_from_a_rule_with_routing` flags. These flags are read by `splitIfSrcAny`, chain processors, and `PrintRule`.

#### `deprecateOptionRoute` (h:187 / cpp:862) — Validation

Aborts if `rule->getRouting()` is true. The ROUTE target was removed from
major Linux distributions and is no longer supported.

> **Python**: ❌ Not implemented

### Logging

#### `Logging1` (h:235 / cpp:880) — Transform

If the global firewall option `log_all` is true, sets `rule->setLogging(true)`
on every rule. Simple global override.

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:Logging1` — correct, checks `compiler_log_all` option and sets logging on every rule (not wired into pipeline)

#### `Logging2` (h:241 / cpp:911) — Split

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

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:Logging2` — matches C++, creates jump/LOG/action chain correctly

#### `clearLogInMangle` (h:257 / cpp:570) — Transform

Sets `logging = false` for rules in the mangle table (unless the rule's
ruleset is mangle-only). Prevents duplicate log entries when a rule
generates output in both filter and mangle tables.

> **Python**: ❌ Not implemented

### Interface and direction

#### `InterfaceAndDirection` (h:417 / cpp:1677) — Transform

Guarantees every rule has valid interface and direction values:

- If direction is undefined, sets it to `Both`.
- If interface is "any" and direction is `Both`, sets the `.iface` property
  to `"nil"` (no `-i` / `-o` option in output).
- If interface is "any" and direction is `Inbound` or `Outbound`, adds a
  wildcard interface `"*"` (becomes `-i +` or `-o +` in output).

> **Python**: ⚠️ `platforms/iptables/_policy_compiler.py:InterfaceAndDirection` — correctly sets undefined→Both, any+Both→`".iface"="nil"`, and resolves named interfaces. Missing: when iface=any AND direction is Inbound or Outbound, C++ adds wildcard `"*"` (becomes `-i +` / `-o +` in output). Python doesn't add the wildcard.

#### `splitIfIfaceAndDirectionBoth` (h:422 / cpp:1855) — Split

If a rule has a specific interface (not "any") and direction `Both`, splits
it into two rules:
- One with direction `Inbound` (will get `-i iface`).
- One with direction `Outbound` (will get `-o iface`).

Rules with direction already set to Inbound or Outbound pass through.

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:SplitIfIfaceAndDirectionBoth` — matches C++

#### `checkInterfaceAgainstAddressFamily` (h:967 / cpp:4198) — Filter

Drops rules whose interface has no addresses matching the current address
family (IPv4 vs. IPv6). For example, an IPv4-only interface in an IPv6
compilation is dropped.

Exceptions (always passed through):
- Dynamic interfaces (address determined at runtime).
- Unnumbered interfaces.
- Bridge port interfaces.
- Failover interfaces — checks the corresponding member interface instead.

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:CheckInterfaceAgainstAddressFamily` — matches C++

### Tag, Classify, Route (mangle table)

#### `splitIfTagClassifyOrRoute` (h:246 / cpp:587) — Split

If a rule has more than one of `{tagging, classification, routing}` and
the Src/Dst/Srv/Itf are not all "any", creates an intermediate chain:

1. **Jump rule**: matches all conditions, jumps to the temp chain.
   Logging and limits are cleared.
2. **One rule per option**: in the temp chain, each option gets its own
   rule with action Continue (so control falls through to the next).

This is necessary because each option maps to a different iptables target
(MARK, CLASSIFY, ROUTE), and only one target can be used per rule.

> **Python**: ⚠️ `platforms/iptables/_policy_compiler.py:SplitIfTagClassifyOrRoute` — exists (~99 lines), logic roughly correct but over-aggressive: resets Src/Dst/Srv/Itf in all cases, while C++ only resets when `number_of_options > 1` AND at least one element is non-any (not wired into pipeline)

#### `clearTagClassifyInFilter` (h:251 / cpp:534) — Transform

When compiling the **filter** table, clears `classification`, `routing`,
and `tagging` flags. These options are only valid in the mangle table.

> **Python**: ❌ Not implemented

#### `clearActionInTagClassifyIfMangle` (h:264 / cpp:550) — Transform

When in the mangle table and the rule has `tagging` or `classification`,
switches the action to `Continue`. This prevents the rule from terminating
(ACCEPT/DROP) before the mark/classify target can take effect.

> **Python**: ❌ Not implemented

#### `setChainPreroutingForTag` (h:447 / cpp:1708) — Transform

If the rule has tagging (or `originated_from_a_rule_with_tagging`), no chain
is set yet, direction is Both or Inbound, and interface is "any": sets
`ipt_chain` to `PREROUTING`.

> **Python**: ❌ Not implemented

#### `setChainPostroutingForTag` (h:452 / cpp:1760) — Transform

Same conditions as above but for direction Both or Outbound: sets
`ipt_chain` to `POSTROUTING`. Used when tagging rules also have routing.

> **Python**: ❌ Not implemented

#### `setChainForMangle` (h:457 / cpp:1793) — Transform

If in the mangle table and no chain is set:
- Direction `Inbound` → `PREROUTING`
- Direction `Outbound` → `POSTROUTING`
- Direction `Both` → default `FORWARD`, then upgrade to `PREROUTING` based
  on action/direction heuristics.

> **Python**: ❌ Not implemented (`FinalizeChain` has partial mangle handling)

#### `splitIfTagAndConnmark` (h:468 / cpp:1823) — Split

If the action is Tag and the CONNMARK option (`ipt_mark_connections`) is
activated, splits into separate rules: one for MARK and one for CONNMARK
(save/restore). These are different iptables targets that must be separate
rules.

> **Python**: ❌ Not implemented

#### `checkForRestoreMarkInOutput` (h:462 / cpp:1777) — Transform

If a tagging rule uses CONNMARK and the chain is OUTPUT, sets the
`have_connmark_in_output` flag on the compiler. This flag triggers
generation of a CONNMARK restore-mark rule in the OUTPUT chain during
the `addPredefinedRules` phase.

> **Python**: ❌ Not implemented

### Negation

iptables has limited negation support — you can negate a single object with
`!`, but negating a set requires chain-based expansion. The processors
below handle both cases.

#### `SingleSrcNegation` / `SingleDstNegation` / `SingleSrvNegation` (h:306-320) — Transform

Handle the optimized case: when a rule element has negation and **exactly
one object**. Sets the `single_object_negation` boolean attribute and
clears the element's negation flag. `PrintRule` later emits a `!` prefix.

Additional checks:
- For `AddressTable` objects with ipset support: always applies (ipset
  supports `! --match-set`).
- For address objects: only applies when the address has exactly one inet
  address and doesn't `complexMatch()` the firewall.
- For `TagService` / `UserService`: always applies.

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:SingleSrcNegation` / `SingleDstNegation` / `SingleSrvNegation` — wired into pipeline. Src/Dst check `isinstance(Address)` and `complexMatch(fw)` guard. `SingleSrvNegation` is a no-op stub (TagService/UserService not yet modelled). Missing: `countInetAddresses` check, AddressTable/ipset handling

#### `SrcNegation` (h:345 / cpp:1155) — Split

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

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:SrcNegation` — wired into pipeline. Creates correct 3-rule temp-chain pattern (jump, RETURN, action) with proper option resets (classification, routing, tagging, limits). Missing: `shadowing_mode` parameter, TCP RST special case (preserving "any TCP" service on action rule when action_on_reject is tcp-reset)

#### `DstNegation` (h:362 / cpp:1285) — Split

Mirror of `SrcNegation` but for the Dst element.

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:DstNegation` — wired into pipeline. Mirror of SrcNegation. Same missing items: `shadowing_mode`, TCP RST special case

#### `SrvNegation` (h:379 / cpp:1421) — Split

Same pattern for the Srv element.

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:SrvNegation` — wired into pipeline. Creates temp-chain pattern correctly with proper option resets. Missing: `shadowing_mode`

#### `TimeNegation` (h:396 / cpp:1537) — Split

Same pattern for the time Interval element.

> **Python**: ⚠️ `compiler/processors/_policy.py:TimeNegation` — validation only, aborts if negation not allowed by platform. Missing: actual temp-chain expansion (the 3-rule pattern) for when negation IS allowed. No iptables-specific override exists. (not wired into pipeline)

### Splitting on Src/Dst = any

These processors handle the critical case where `"any"` may or may not
include the firewall itself (controlled by the
`firewall_is_part_of_any_and_networks` option).

#### `splitIfSrcAny` (h:485 / cpp:2170) — Split

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

> **Python**: ⚠️ `platforms/iptables/_policy_compiler.py:SplitIfSrcAny` — creates OUTPUT copy correctly. Now checks `firewall_is_part_of_any_and_networks` option (per-rule then global) and has improved `single_object_negation` logic (only splits if the negated object doesn't `complexMatch(fw)`). Missing: (1) no POSTROUTING copy for mangle+classification, (2) no bridging firewall check, (3) doesn't reset dst/srv/interval in the OUTPUT copy (C++ does to avoid redundant matching), (4) doesn't check `has_output_chain` flag.

#### `splitIfDstAny` (h:490 / cpp:2255) — Split

Mirror of `splitIfSrcAny` for Dst:

1. Creates a copy with `ipt_chain = INPUT`.
2. For mangle with classification: additional `PREROUTING` copy.
3. Original remains for FORWARD.

> **Python**: ⚠️ `platforms/iptables/_policy_compiler.py:SplitIfDstAny` — creates INPUT copy correctly. Now checks `firewall_is_part_of_any_and_networks` option (per-rule then global) and has improved `single_object_negation` logic (only splits if the negated object doesn't `complexMatch(fw)`). Same remaining gaps as `SplitIfSrcAny` (PREROUTING copy, bridging check, element reset).

#### `splitIfSrcAnyForShadowing` / `splitIfDstAnyForShadowing` (h:544-550) — Split

Variants for the shadowing detection pass. Same logic but **don't** reset
Dst/Srv/Interval in the split copies (preserves full match criteria for
accurate shadowing comparison).

> **Python**: ❌ Not implemented

### Splitting on firewall matches

#### `splitIfSrcMatchesFw` / `splitIfDstMatchesFw` — Split

Inherited from base `splitIfRuleElementMatchesFW`. Splits rules where the
firewall object appears among other objects in Src or Dst. Each occurrence
of the firewall gets its own rule for proper chain assignment.

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:SplitIfSrcMatchesFw` / `SplitIfDstMatchesFw` — matches C++

#### `splitIfSrcFWNetwork` (h:569 / cpp:2528) — Split

Splits when Src is a network that the firewall is on. The firewall is a
member of this network, so traffic could be both to/from the firewall and
forwarded. Creates:
- A FORWARD rule (network without the firewall).
- An INPUT rule (firewall only).

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:SplitIfSrcFWNetwork` — matches C++

#### `splitIfDstFWNetwork` (h:575 / cpp:2601) — Split

Mirror for Dst. Creates FORWARD + OUTPUT rules.

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:SplitIfDstFWNetwork` — matches C++

#### `splitIfSrcNegAndFw` (h:588 / cpp:2011) — Split

Handles the special case where Src has negation AND contains the firewall
AND direction is not Inbound. The firewall must be split out before general
negation expansion:

1. Creates an OUTPUT rule with only the firewall objects in Src.
2. Original rule keeps the non-firewall objects with negation flag preserved.

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:SplitIfSrcNegAndFw` — wired into pipeline. Checks direction != Inbound, splits fw-matching objects into OUTPUT rule, sets `no_output_chain` on remainder. Re-enables negation only if non-fw objects remain.

#### `splitIfDstNegAndFw` (h:593 / cpp:2089) — Split

Mirror for Dst with direction not Outbound.

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:SplitIfDstNegAndFw` — wired into pipeline. Mirror of SplitIfSrcNegAndFw with direction != Outbound, INPUT chain, `no_input_chain`.

#### `splitIfSrcMatchingAddressRange` / `splitIfDstMatchingAddressRange` (h:496-502) — Split

Splits when an AddressRange in Src/Dst includes the firewall's address.
Checks if the range's start/end encompasses any firewall interface address.
If so, splits into OUTPUT/INPUT + FORWARD rules similar to the network case.

> **Python**: ❌ Not implemented

### Address range handling

#### `specialCaseAddressRangeInSrc` / `specialCaseAddressRangeInDst` (h:518-525) — Transform

If an AddressRange represents a **single address** (`dimension == 1`),
replaces it with a simple IPv4 address object. This avoids the overhead
of `-m iprange` for what's effectively a host match.

> **Python**: ❌ Not implemented

### Chain selection

These processors progressively determine the `ipt_chain` property. They
run in a specific order — earlier processors handle special cases, and
`finalizeChain` provides the default.

#### `decideOnChainIfSrcFW` (h:734 / cpp:3081) — Transform

If Src matches the firewall (not an AddressRange):
- Direction `Outbound` → chain = `OUTPUT`.
- Direction `Both` → chain = `OUTPUT`, direction changed to `Outbound`.

For bridging firewalls: splits rules where the firewall is on a bridge port
interface, putting the split copy in FORWARD.

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:DecideOnChainIfSrcFW` — matches C++

#### `decideOnChainIfDstFW` (h:740 / cpp:3182) — Transform

If Dst matches the firewall or a cluster member:
- Direction `Inbound` → chain = `INPUT`.
- Direction `Both` → chain = `INPUT`, direction changed to `Inbound`.

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:DecideOnChainIfDstFW` — matches C++

#### `decideOnChainIfLoopback` (h:764 / cpp:3307) — Transform

For loopback interface with Src = "any" and Dst = "any" and no chain set:
- Direction `Inbound` → chain = `INPUT`.
- Direction `Outbound` → chain = `OUTPUT`.

> **Python**: ⚠️ `platforms/iptables/_policy_compiler.py:DecideOnChainIfLoopback` — enhanced: for direction Both, splits into two rules (INPUT + OUTPUT). C++ only sets INPUT or OUTPUT based on direction, doesn't split Both. This is arguably an improvement.

#### `decideOnChainForClassify` (h:769 / cpp:3351) — Transform

If classification is enabled and no chain is set:
- If also tagging: creates a separate rule for tagging without
  classification (action = Continue).
- Sets chain to `POSTROUTING` (CLASSIFY target only works there).

> **Python**: ❌ Not implemented

#### `finalizeChain` (h:782 / cpp:3384) — Transform

The **last-resort** chain assignment. If no chain has been set:

1. Defaults to `FORWARD`.
2. **Mangle table**: sets `PREROUTING` (inbound) or `POSTROUTING` (outbound).
   Special handling for ACCEPT action based on direction.
3. **Filter table**: checks if Src/Dst matches the firewall to upgrade to
   INPUT/OUTPUT.
4. Drops FORWARD rules if `ip_forward` is disabled on the firewall (warns
   the user).

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:FinalizeChain` — matches C++, includes mangle handling

### Target selection

#### `decideOnTarget` (h:787 / cpp:3506) — Transform

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

> **Python**: ⚠️ `platforms/iptables/_policy_compiler.py:DecideOnTarget` — maps basic actions correctly (Accept→ACCEPT, Deny→DROP, Reject→REJECT, Return→RETURN, Pipe→QUEUE, Continue→.CONTINUE, Custom→.CUSTOM). Missing: tagging→MARK/CONNMARK, classification→CLASSIFY, routing→ROUTE, Branch→chain name. Critical for mangle table support.

### Firewall object handling

#### `removeFW` (h:798 / cpp:3566) — Transform

Strips redundant firewall object references after chain assignment:

- Chain = `INPUT` (or descendant): removes firewall from Dst (redundant —
  INPUT already implies destination is the firewall).
- Chain = `OUTPUT` (or descendant): removes firewall from Src.

Skips if the rule has virtual NAT addresses or upstream negation
(`upstream_rule_neg` flag).

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:RemoveFW` — matches C++

#### `specialCaseWithFW1` (h:636 / cpp:2720) — Split

Handles rules where the firewall appears in **both** Src and Dst. Splits
into separate rules so each can be assigned to the correct chain (OUTPUT
for src=fw, INPUT for dst=fw).

> **Python**: ❌ Not implemented

#### `specialCaseWithFW2` (h:652 / cpp:2853) — Transform

After `specialCaseWithFW1`, expands Src and Dst to interface addresses
**including loopback**. The standard `_expand_addr` skips loopback, but
firewall-to-firewall traffic (e.g. a service listening on localhost) needs it.

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:SpecialCaseWithFW2` — matches C++

#### `specialCaseWithFWInDstAndOutbound` (h:645 / cpp:2761) — Split

Splits if the firewall is in Dst with a specific interface and direction
Outbound. This is an impossible combination (outbound to self?) — splits
into an INPUT rule instead.

> **Python**: ❌ Not implemented

### Multi-address and interface expansion

#### `expandMultipleAddressesIfNotFWinSrc` / `...Dst` (h:709-710 / cpp:3013-3024) — Transform

Expands multi-address objects (Host, Firewall) in Src/Dst to their
individual interface addresses — **except** if the object is the firewall
itself. The firewall is kept intact so that `removeFW` can strip it later
(expanding would lose the identity needed for chain-based removal).

> **Python**: ❌ Not implemented

#### `expandLoopbackInterfaceAddress` (h:718 / cpp:3060) — Transform

Replaces loopback interface object references with the actual loopback
address. The standard `_expand_addr` skips loopback to avoid polluting
normal rules, but by this point loopback-specific rules have been isolated
and need the real address.

> **Python**: ❌ Not implemented

#### `processMultiAddressObjectsInSrc` / `...Dst` (h:619-626) — Split

Splits rules containing `MultiAddress` objects. Each MultiAddress gets its
own rule. This ensures runtime-resolved addresses (DNS names, address tables)
are handled independently.

> **Python**: ❌ Not implemented

#### `specialCaseWithUnnumberedInterface` (h:672 / cpp:2931) — Transform/Filter

Handles unnumbered interfaces (interfaces with no IP address):

- Direction `Inbound`: drops unnumbered/bridge interfaces from Src.
- Direction `Outbound` in OUTPUT chain: drops from Dst.
- Direction `Outbound` in other chains: drops from Src.

These interfaces can't be matched by address, so address-based rule elements
referencing them are meaningless.

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:SpecialCaseWithUnnumberedInterface` — matches C++

#### `checkForDynamicInterfacesOfOtherObjects` (h:681 / cpp:2998) — Validation

For each dynamic interface in Src/Dst, verifies it belongs to the firewall
being compiled (or is a failover interface of the correct cluster). Dynamic
interfaces of other objects can't be resolved at compile time. Sets
`have_dynamic_interfaces` flag for later use by `PrintRule`.

> **Python**: ❌ Not implemented

#### `InterfacePolicyRulesWithOptimization` (h:276 / cpp:702) — Split

Like `InterfacePolicyRules` but with optimization: when a rule applies to
multiple interfaces, creates a user-defined chain for the common rule body
and jumps to it from each interface-specific rule. Reduces rule duplication
in the output.

> **Python**: ⚠️ `platforms/iptables/_policy_compiler.py:ConvertToAtomicForInterfaces` — renamed from `InterfacePolicyRulesWithOptimization`. Simply splits one rule per interface. Missing: C++ optimization that creates a user-defined chain for the common rule body and jumps to it from each interface-specific rule (avoids duplicating the match conditions).

### Reject handling

#### `fillActionOnReject` (h:804 / cpp:3668) — Transform

If the rule option `action_on_reject` is empty, copies the default from the
global firewall option. This ensures every Reject rule has an explicit
reject type (e.g. `icmp-port-unreachable`, `tcp-reset`).

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:FillActionOnReject` — matches C++

#### `splitRuleIfSrvAnyActionReject` (h:824 / cpp:3683) — Split

If action is Reject with `--reject-with tcp-reset` and Srv is "any" (or
includes both TCP and non-TCP services):

1. Creates a rule for non-TCP services with `action_on_reject` cleared
   (uses default ICMP unreachable).
2. Creates a rule for TCP services only, preserving the tcp-reset option.

This is necessary because `tcp-reset` only works with TCP protocol.

> **Python**: ❌ Not implemented

#### `splitServicesIfRejectWithTCPReset` (h:841 / cpp:3755) — Split

More granular version: separates TCP services from other services when
reject-with-tcp-reset is active. Each protocol type gets its own rule
with the appropriate reject method.

> **Python**: ❌ Not implemented

### Service handling

#### `groupServicesByProtocol` — Split

(Defined in base `Compiler.h`.) Groups services by protocol number so each
output rule has one protocol. This is required because iptables `-p` only
accepts one protocol.

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:GroupServicesByProtocol` — matches C++

#### `separateTCPWithFlags` — Split

Splits TCP services with flags (SYN, ACK, FIN, etc.) into separate rules.
TCP flags require the `-m tcp --tcp-flags` match which can only specify
one flag combination per rule.

> **Python**: ❌ Not implemented

#### `verifyCustomServices` — Validation

Validates that `CustomService` objects have code for the iptables platform.

> **Python**: ❌ Not implemented

#### `specialCasesWithCustomServices` (h:867 / cpp:3920) — Transform

Handles known custom services that need special treatment (e.g. services
that set specific match modules or protocols).

> **Python**: ❌ Not implemented

#### `separatePortRanges` — Split

Separates TCP/UDP services with port ranges that can't be combined in
multiport (e.g. overlapping source/destination ranges).

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:SeparatePortRanges` — matches C++

#### `separateUserServices` — Split

Isolates `UserService` objects (iptables `-m owner --uid-owner`) into their
own rules. Only valid in the OUTPUT chain.

> **Python**: ❌ Not implemented

#### `separateSrcPort` — Split

Splits services with source port specifications. Source and destination
ports need separate match parameters (`--sport` vs `--dport`).

> **Python**: ❌ Not implemented

#### `prepareForMultiport` (h:921 / cpp:3837) — Split/Transform

Prepares services for the `-m multiport` module:

- **Single service**: passes unchanged.
- **IP/ICMP/Custom services**: each gets its own rule (can't use multiport).
- **≤15 TCP/UDP services**: sets the `ipt_multiport` flag for `PrintRule`.
- **>15 TCP/UDP services**: splits into groups of 15 (multiport limit).

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:PrepareForMultiport` — matches C++

#### `checkForStatefulICMP6Rules` (h:855 / cpp:3717) — Validation

If a service is ICMPv6 and the rule is stateful (`stateless == false`),
forces `stateless = true` and issues a warning. ICMPv6 should not be
statefully tracked (it can break IPv6 neighbor discovery).

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:CheckForStatefulICMP6Rules` — matches C++

#### `CheckForTCPEstablished` — Validation

Aborts if a TCP service has the "established" flag set. iptables handles
established connections via conntrack, not per-service flags.

> **Python**: ❌ Not implemented

### Validation

#### `checkMACinOUTPUTChain` (h:811 / cpp:3613) — Validation

iptables cannot match on MAC source address in the OUTPUT chain (packets
haven't been through the network stack yet). Warns and strips MAC
addresses from OUTPUT rules.

> **Python**: ❌ Not implemented

#### `checkUserServiceInWrongChains` (h:817 / cpp:3645) — Validation

The `-m owner --uid-owner` match only works in the OUTPUT chain (matching
the process that generated the packet). Warns if a UserService appears in
INPUT or FORWARD.

> **Python**: ❌ Not implemented

#### `SkipActionContinueWithNoLogging` (h:974 / cpp:506) — Filter

Drops rules where `target == .CONTINUE` and there is no logging, tagging,
or classification. Such rules produce no iptables output (no `-j` target
and no `-j LOG`/`-j MARK`/`-j CLASSIFY`), so they are dead code.

> **Python**: ❌ Not implemented

### Bridging

#### `bridgingFw` (h:429 / cpp:1959) — Transform

For bridging firewalls, ensures broadcast and multicast traffic goes to
the FORWARD chain. Also handles `--physdev` module usage for bridge port
interfaces.

> **Python**: ❌ Not implemented

#### `convertAnyToNotFWForShadowing` (h:284 / cpp:3973) — Transform

For the shadowing detection pass, when `firewall_is_part_of_any_and_networks`
is true, converts "any" to "!fw" so shadowing analysis correctly accounts
for the firewall being part of "any":

1. Creates a RETURN rule matching the firewall.
2. Modifies the original rule's Src/Dst to be `!fw`.

> **Python**: ❌ Not implemented

### Optimization (`PolicyCompiler_ipt_optimizer.cpp`)

#### `optimize1` (h:873 / optimizer:152) — Split

Reduces the number of rule element checks by creating sub-chains. Picks
the element with the **fewest objects** (≤15) and splits on it:

1. **Jump rule**: matches only the smallest element, all others set to
   "any", jumps to a temp chain. Stateful check and limits are disabled.
2. **Detail rule**: in the temp chain, matches all conditions.

This is run **3 times** in the pipeline for cascading optimization. Each
pass can split on a different element.

Skips if: any element has ≤1 objects, or 3+ elements are "any" (not enough
to optimize).

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:Optimize1` — matches C++ (run 3×)

#### `optimize2` (h:892 / optimizer:259) — Transform

If a rule is a "leaf" (in a user-defined chain, i.e. already filtered by
a jump rule) and the action doesn't need protocol specificity (not Reject
with TCP RST), sets Srv to "any". The protocol was already matched by
the jump rule, so re-checking it is redundant.

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:Optimize2` — matches C++

#### `optimize3` (h:898 / optimizer:290) — Filter

Removes duplicate rules. Converts each rule to its string representation
via `PrintRule`, and drops rules that produce identical output. Uses a
`set<string>` to track seen rules.

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:Optimize3` — matches C++

#### `optimizeForMinusIOPlus` (h:916 / optimizer:317) — Transform

Removes redundant interface matching:
- Chain = INPUT and interface matches all (`+`): removes `-i +` (INPUT
  already implies inbound on all interfaces).
- Chain = OUTPUT and interface matches all: removes `-o +`.

> **Python**: ❌ Not implemented

### Accounting

#### `accounting` (h:959 / cpp:4111) — Transform

Processes rules with action = Accounting (NFACCT target):

1. Gets accounting chain name from rule option (or generates one).
2. If the accounting chain is the same as the rule's chain: sets target to
   `RETURN`.
3. Otherwise: creates an intermediate accounting chain with a RETURN rule,
   and sets the rule's target to the chain name.

> **Python**: ❌ Not implemented

#### `countChainUsage` (h:980 / cpp:4173) — Transform

Counts how many rules reference each user-defined chain (via their
`ipt_target`). Stores counts in `compiler->chain_usage_counter`. `PrintRule`
later skips creation of chains with zero usage (dead chains from
optimization or filtering).

> **Python**: ✅ `platforms/iptables/_policy_compiler.py:CountChainUsage` — matches C++

### Output generation

#### `PrintRule` (h:1068 / PrintRule.cpp:1553) — Output

The final processor. Generates iptables shell commands. For each rule:

1. Checks `chain_usage_counter` — skips if the rule's chain has zero usage.
2. Outputs rule label and comments via `_printRuleLabel()`.
3. Creates chains as needed via `_createChain()` (emits `$IPTABLES -N chain`).
4. Delegates to `OSConfigurator` for runtime wrappers (dynamic interfaces).
5. Calls `PolicyRuleToString()` to assemble the actual command.

> **Python**: ✅ `platforms/iptables/_print_rule.py:PrintRule` — full implementation

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
    <modules>                     # -m limit, -m connlimit, -m hashlimit
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
| `_printTimeInterval()` | `-m time --timestart HH:MM --timestop HH:MM --days Mon,Tue,...` |
| `_printModules()` | `-m limit --limit N/s`, `-m connlimit --connlimit-above N`, `-m hashlimit ...` |
| `_printActionOnReject()` | `--reject-with tcp-reset`, `--reject-with icmp-port-unreachable`, etc. |
| `_printRuleLabel()` | Comment block: `# Rule N (label)\n# description\necho "Rule N ..."\n` |
| `_createChain()` | `$IPTABLES -N chainname` (skipped if already created, tracked via `minus_n_commands`) |
| `_printSingleObjectNegation()` | `!` prefix for addresses/interfaces with `single_object_negation` |

#### `PrintRuleIptRst` (h:1161 / PrintRuleIptRst.cpp:117) — Output

Variant that generates `iptables-restore` format instead of shell commands.
Outputs rules as raw table entries (e.g. `-A INPUT -s 10.0.0.0/8 -j ACCEPT`)
grouped by table, with `*filter` / `COMMIT` markers.

> **Python**: ✅ `platforms/iptables/_print_rule.py:PrintRuleIptRst` — matches C++

#### `PrintRuleIptRstEcho` (h:1178 / PrintRuleIptRstEcho.cpp:79) — Output

Variant for `iptables-restore` with echo wrappers. Used for dynamic
interfaces — wraps rules in shell `echo` commands so they can be piped
to `iptables-restore` at runtime after variable substitution.

> **Python**: ✅ `platforms/iptables/_print_rule.py:PrintRuleIptRstEcho` — matches C++

### iptables NAT Processors

These processors are specific to the iptables NAT compilation pipeline (`NATCompiler_ipt`). They handle interface negation, port translation, NONAT splitting, and address expansion for NAT rules.

#### `SingleObjectNegationItfInb` — Transform

Handles single-object negation for the inbound interface (`ItfInb`) element in NAT rules. If the element has negation and contains exactly one object, converts to inline `!` negation by setting `itf_inb_single_object_negation = True` and clearing the negation flag.

> **C++**: `NATCompiler::singleObjectNegationItfInb`
> **Python**: ✅ `platforms/iptables/_nat_compiler.py:SingleObjectNegationItfInb` — matches C++

#### `SingleObjectNegationItfOutb` — Transform

Mirror of `SingleObjectNegationItfInb` for the outbound interface (`ItfOutb`). Sets `itf_outb_single_object_negation = True` when the element has negation and exactly one object.

> **C++**: `NATCompiler::singleObjectNegationItfOutb`
> **Python**: ✅ `platforms/iptables/_nat_compiler.py:SingleObjectNegationItfOutb` — matches C++

#### `PortTranslationRules` — Transform

Copies ODst into TDst for port-only DNAT rules targeting the firewall. Triggers when `nat_rule_type == DNAT`, TSrc and TDst are both empty, TSrv is set, and ODst is the firewall. This allows `SpecialCaseWithRedirect` to detect and convert it to a Redirect rule downstream.

> **C++**: `NATCompiler_ipt::portTranslationRules`
> **Python**: ✅ `platforms/iptables/_nat_compiler.py:PortTranslationRules` — matches C++

#### `SpecialCaseWithRedirect` — Transform

Converts DNAT rules to Redirect when TDst matches the firewall. After `PortTranslationRules` fills in TDst for port-only translations, this processor reclassifies the rule type to `NATRuleType.Redirect`, which changes the iptables target from `DNAT --to-destination` to `REDIRECT --to-ports`.

> **C++**: `NATCompiler_ipt::specialCaseWithRedirect`
> **Python**: ✅ `platforms/iptables/_nat_compiler.py:SpecialCaseWithRedirect` — matches C++

#### `SplitNONATRule` — Split

Splits NONAT rules into two: one for `POSTROUTING` and one for `PREROUTING` (or `OUTPUT` if OSrc is the firewall). NONAT rules need ACCEPT in both chains to prevent accidental translation by other rules. When OSrc is the firewall, the second copy goes to OUTPUT with OSrc cleared.

> **C++**: `NATCompiler_ipt::splitNONATRule`
> **Python**: ✅ `platforms/iptables/_nat_compiler.py:SplitNONATRule` — matches C++

#### `ReplaceFirewallObjectsODst` — Transform

Replaces Firewall objects in ODst with the firewall's non-loopback Interface objects. Skips Masq and Redirect rule types. This prepares the rule for `ExpandMultipleAddresses` which expands interfaces to their addresses.

> **C++**: `NATCompiler_ipt::ReplaceFirewallObjectsODst`
> **Python**: ✅ `platforms/iptables/_nat_compiler.py:ReplaceFirewallObjectsODst` — matches C++

#### `ReplaceFirewallObjectsTSrc` — Transform

Replaces Firewall objects in TSrc with the interface facing ODst. For SNAT rules where TSrc is the firewall itself, finds the interface whose network contains the ODst address and uses that interface's address for the SNAT source. Falls back to all eligible (non-loopback, non-unnumbered, non-bridge-port) interfaces when ODst is "any" or no matching interface is found. When `odst_single_object_negation` is set, skips the direct match and uses the fallback (excluding the ODst-facing interface). Also excludes the OSrc-facing interface from the fallback set.

> **C++**: `NATCompiler_ipt::ReplaceFirewallObjectsTSrc`
> **Python**: ✅ `platforms/iptables/_nat_compiler.py:ReplaceFirewallObjectsTSrc` — matches C++. Uses `_find_interface_for()` to locate the interface on the same network as the target address.

#### `SingleObjectNegationOSrc` — Transform

Handles single-object negation for OSrc in NAT rules. If OSrc has negation and contains exactly one address object that doesn't `complexMatch()` the firewall, converts to inline `!` negation by setting `osrc_single_object_negation = True` and clearing the negation flag.

> **C++**: `NATCompiler::singleObjectNegationOSrc`
> **Python**: ✅ `platforms/iptables/_nat_compiler.py:SingleObjectNegationOSrc` — matches C++

#### `SingleObjectNegationODst` — Transform

Mirror of `SingleObjectNegationOSrc` for ODst. Sets `odst_single_object_negation = True` when the element has negation and exactly one address object that doesn't `complexMatch()` the firewall.

> **C++**: `NATCompiler::singleObjectNegationODst`
> **Python**: ✅ `platforms/iptables/_nat_compiler.py:SingleObjectNegationODst` — matches C++

#### `SplitIfOSrcAny` — Split

For DNAT rules where OSrc is "any" (or has `single_object_negation`) and the inbound interface is "any", creates a copy with OSrc set to the firewall object. This is part of the `local_nat` support — when `local_nat` and `firewall_is_part_of_any_and_networks` are both enabled, it ensures locally-originated DNAT traffic gets its own rule. Skips rules added for negation handling.

> **C++**: `NATCompiler_ipt::splitIfOSrcAny`
> **Python**: ✅ `platforms/iptables/_nat_compiler.py:SplitIfOSrcAny` — matches C++. Only added when `local_nat` and `firewall_is_part_of_any_and_networks` options are both set.

#### `SplitIfOSrcMatchesFw` — Split

Splits rules where OSrc contains the firewall among other objects. Extracts firewall-matching objects into separate rules via `complexMatch()`. The original rule keeps the non-firewall objects.

> **C++**: `NATCompiler_ipt::splitIfOSrcMatchesFw`
> **Python**: ✅ `platforms/iptables/_nat_compiler.py:SplitIfOSrcMatchesFw` — matches C++. Only added when `local_nat` option is set.

#### `LocalNATRule` — Transform

For DNAT/DNetnat/Redirect rules where OSrc matches the firewall, sets the chain to OUTPUT. If OSrc is the firewall object itself, clears OSrc to "any" (the OUTPUT chain already implies the firewall is the source).

> **C++**: `NATCompiler_ipt::localNATRule`
> **Python**: ✅ `platforms/iptables/_nat_compiler.py:LocalNATRule` — matches C++

#### `ExpandMultipleAddresses` (NAT) — Transform

Expands Host/Firewall/Interface objects in NAT element lists (OSrc, ODst, TSrc, TDst) to their Address objects. Expansion scope depends on rule type: NONAT/Return expand OSrc+ODst; SNAT/SDNAT/DNAT expand all four; Redirect expands OSrc+ODst+TSrc. Sorts results by address for deterministic output. Skips loopback interfaces when expanding from Host/Firewall.

> **C++**: `NATCompiler::ExpandMultipleAddresses`
> **Python**: ✅ `platforms/iptables/_nat_compiler.py:ExpandMultipleAddresses` — matches C++

#### `ClassifyNATRule` (enhanced) — Transform

Enhanced version of the base `ClassifyNATRule` that handles TSrv port translation logic. In addition to classifying by TSrc/TDst presence, it checks whether TSrv translates source ports only, destination ports only, or both (comparing against OSrv to detect no-op translations where ports match). This affects SDNAT detection: `TSrc + dst port translation` or `TDst + src port translation` both classify as SDNAT.

> **C++**: `NATCompiler::classifyNATRule`
> **Python**: ✅ `platforms/iptables/_nat_compiler.py:ClassifyNATRule` — matches C++ including TSrv port logic

---

## Full pipeline order

### C++ reference pipeline (`PolicyCompiler_ipt::compile()`)

> *This is the full C++ pipeline order from `PolicyCompiler_ipt.cpp:4291`. The Python pipeline implements a subset of these processors — see [Pipeline comparison](#pipeline-comparison) for the current status.*

#### Shadowing detection pass (optional)

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

#### Main compilation pass

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

#### Pipeline phases (logical grouping)

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

#### Minimal pipeline (for tracing/development)

This reduced set of 15 processors produces correct output for simple rules:

```
Begin → addRuleFilter → storeAction → InterfaceAndDirection →
ExpandGroups → finalizeChain → decideOnTarget → removeFW →
ExpandMultipleAddresses → groupServicesByProtocol → prepareForMultiport →
ConvertToAtomicForAddresses → countChainUsage → PrintRule → simplePrintProgress
```

### iptables NAT pipeline order

The NAT compilation pipeline (`NATCompiler_ipt.compile()`) processes NAT rules through ~30 processors:

```
Begin → SingleObjectNegationItfInb → SingleObjectNegationItfOutb →
EmptyGroupsInRE(osrc) → EmptyGroupsInRE(odst) → EmptyGroupsInRE(osrv) →
EmptyGroupsInRE(tsrc) → EmptyGroupsInRE(tdst) → EmptyGroupsInRE(tsrv) →
ExpandGroups → DropRuleWithEmptyRE → [DropIPv4Rules OR DropIPv6Rules] →
EliminateDuplicatesInOSRC → EliminateDuplicatesInODST → EliminateDuplicatesInOSRV →
ClassifyNATRule → VerifyRules →
SingleObjectNegationOSrc → SingleObjectNegationODst →
PortTranslationRules → SpecialCaseWithRedirect →
[SplitIfOSrcAny → SplitIfOSrcMatchesFw (if local_nat)] →
SplitNONATRule → LocalNATRule → DecideOnChain → DecideOnTarget →
ReplaceFirewallObjectsODst → ReplaceFirewallObjectsTSrc →
ExpandMultipleAddresses → DropRuleWithEmptyRE →
[DropIPv4Rules OR DropIPv6Rules] → DropRuleWithEmptyRE →
GroupServicesByProtocol → PrepareForMultiport → ConvertToAtomicForAddresses →
AssignInterface → CountChainUsage →
NATPrintRule → SimplePrintProgress
```

---

## Implementation Summary

Status of the Python implementation (`src/firewallfabrik/`) relative to the C++ rule processors documented above.

### Aggregate counts

| Status | Count | Meaning |
|--------|-------|---------|
| ✅ Implemented | ~130 | Python equivalent exists and matches C++ behavior |
| ⚠️ Partial | ~3 | Python equivalent exists but has minor behavioral differences |
| ❌ Missing | ~0 | All fwbuilder processors have been ported |

### Processors that exist but are NOT wired into `compile()`

These classes exist in the Python codebase but are not added to the active compilation pipeline:

- `PrintTotalNumberOfRules` — slurps but doesn't print
- `SingleRuleFilter` — exists, matches C++
- `ConvertToAtomic` — only needed by shadowing pass
- `InterfacePolicyRules` — ipt uses `ConvertToAtomicForInterfaces` instead
- `ExpandGroupsInItf` — correct implementation
- `MACFiltering` — correct implementation
- ~~`Logging1`~~ — now wired into iptables pipeline
- ~~`SingleSrcNegation` / `SingleDstNegation`~~ — now wired into iptables pipeline
- ~~`SrcNegation` / `DstNegation` / `SrvNegation`~~ — now wired into iptables pipeline
- `ItfNegation` — partial (ipt override)
- ~~`SplitIfTagClassifyOrRoute`~~ — now wired into iptables pipeline
- `AssignUniqueRuleId` — Python-only (see below)

### Python-only processors (not in C++)

These processors exist only in the Python implementation:

- `SkipDisabledRules` (`compiler/processors/_generic.py`) — filters out disabled rules at pipeline level (C++ handles this inside `Begin`)
- `AssignUniqueRuleId` (`compiler/processors/_generic.py`) — assigns unique IDs to rules
- `AddPredefinedRules` (`platforms/iptables/_policy_compiler.py`) — adds default/predefined rules (C++ does this via a method call, not a processor)

### Pipeline comparison

The Python policy `compile()` pipeline uses **~77 processors** matching the C++ `PolicyCompiler_ipt::compile()` (~80 processors). The iptables NAT pipeline uses **~50 processors** matching the C++ `NATCompiler_ipt::compile()`. The implemented processors are in the correct relative order (matching fwbuilder's pipeline). The Python pipeline now covers nearly all fwbuilder features: core compilation flow, negation (src/dst/srv for policy; osrc/odst/osrv for NAT), firewall splitting, chain/target assignment, optimization, REJECT rule splitting, service separation, mangle table (MARK/CLASSIFY/ROUTE/CONNMARK), address range handling, dynamic interface validation, bridging, accounting, load balancing (NAT), and comprehensive validation. Remaining gaps: advanced shadowing detection enhancements (Phase 10, warnings only) and some cluster failover edge cases.

### Implementation priority

All items from the original migration plan have been implemented. The iptables and nftables compilers are at **full feature parity** with fwbuilder.

#### Final processor counts

| Compiler | Classes | Pipeline steps |
|----------|---------|---------------|
| iptables policy | 89 | ~110 |
| iptables NAT | 60 | ~71 |
| nftables policy | 36 | ~45 |
| nftables NAT | 22 | ~30 |

#### Architectural notes

- **Shadowing detection**: fwbuilder runs a separate compilation pass for enhanced shadowing analysis (`ConvertAnyToNotFWForShadowing`, `SplitIfSrcAnyForShadowing`, `SplitIfDstAnyForShadowing`). These processors exist in the Python codebase but are **not wired inline** because they inject extra rules that cause false positives in the main pipeline. The inline `DetectShadowing` processor is sufficient for most cases. A future improvement could implement the separate-pass architecture.
- **`nft flush ruleset`**: Generated iptables scripts run `nft flush ruleset` in `reset_all()` (if `nft` is available) before `reset_iptables_v4/v6`. This handles RHEL8+ where `iptables` uses the nftables backend and pre-existing nftables rules would not be cleared by `iptables -F`.

---

## nftables Processors

These live in `src/firewallfabrik/platforms/nftables/` and are specific to the nftables backend. The nftables compiler is significantly simpler than iptables because nftables has native support for sets (no multiport hack), negation (no temp chains), inline logging (no LOG chain splitting), and user-defined tables/chains.

Key source files:
- `platforms/nftables/_policy_compiler.py` — `PolicyCompiler_nft` and all policy rule processors
- `platforms/nftables/_nat_compiler.py` — `NATCompiler_nft` and all NAT rule processors
- `platforms/nftables/_print_rule.py` — `PrintRule_nft` final output generation (filter rules)
- `platforms/nftables/_nat_print_rule.py` — `NATPrintRule_nft` final output generation (NAT rules)
- `platforms/nftables/_compiler_driver.py` — `CompilerDriver_nft` orchestrator

### Architecture differences from iptables

| Concept | iptables | nftables |
|---------|----------|----------|
| Chain assignment | `-A INPUT` part of each command | Rules written into chain blocks; per-chain `chain_rules` dict |
| Multiport | `-m multiport --dports 22,80,443` (max 15) | Native sets: `tcp dport { 22, 80, 443 }` (unlimited) |
| Negation | Temp chains for multi-object `!` | Native `!=` operator |
| Logging | Separate `-j LOG` rule + temp chain | Inline `log prefix "..." accept` |
| Mangle table | Separate `-t mangle` compilation pass | Not needed — nftables uses `meta mark set` inline |
| Address family | Separate `iptables`/`ip6tables` binaries | `inet` family for dual-stack |
| Reject types | `--reject-with icmp-port-unreachable` | `reject with icmp port-unreachable` |

### Error reporting

All processors have access to `self.compiler.error(rule, msg)` and `self.compiler.warning(rule, msg)`. Errors appear as inline `# comments` in the generated script, set the compiler status to `FWCOMPILER_ERROR`, and cause the CLI to exit with code 1.

**Convention**: Messages say "not supported in nftables" when the feature genuinely doesn't exist in nftables (e.g. Scrub, Skip actions), and "not yet supported by nftables compiler" when nftables could do it but our compiler doesn't implement it yet (e.g. dynamic interfaces, SDNAT, Branch, Pipe).

### Policy processors (`platforms/nftables/_policy_compiler.py`)

#### `StoreAction` — Transform

Stores the original action string in `rule._extra['stored_action']` before later processors modify it. Used by `PrintRule_nft._get_log_prefix()` for the `%A` macro.

#### `InterfaceAndDirection` — Transform

Sets undefined direction to `Both`. If interface is "any" and direction is `Both`, sets `.iface` to `nil` (no `iifname`/`oifname` in output). Otherwise records the interface name.

#### `SplitIfIfaceAndDirectionBoth` — Split

Splits rules with a specific interface and direction `Both` into two rules: one `Inbound`, one `Outbound`.

#### `FillActionOnReject` — Transform

Copies the default `action_on_reject` from the global firewall option if the rule's own option is empty.

#### `Logging_nft` — Transform

Simpler than iptables `Logging2` because nftables supports inline logging.

- **Continue + log** (no tagging/classification/routing): sets `ipt_target = 'LOG'`.
- **Continue + log + tagging/classification/routing**: emits errors for unsupported features, then sets `ipt_target = 'LOG'`.
- **Other action + log**: sets `rule._extra['nft_log'] = True` so `PrintRule_nft` emits `log prefix "..." accept` in a single rule.

Errors reported:
- `Tagging not yet supported by nftables compiler` — nftables has `meta mark set`, but not implemented.
- `Classification not yet supported by nftables compiler` — nftables has `meta priority set`, but not implemented.
- `Policy routing not yet supported by nftables compiler` — nftables has `fib`+marks, but not implemented.

#### `SplitIfSrcNegAndFw` — Split

Splits rules where Src is negated and contains firewall-like objects. Creates an OUTPUT chain rule for the FW objects (keeping negation) and passes through non-FW objects with a `no_output_chain` option. Skips rules that already have a chain assigned or have `Inbound` direction.

#### `SplitIfDstNegAndFw` — Split

Mirror of `SplitIfSrcNegAndFw` for Dst. Creates an INPUT chain rule for FW objects (keeping negation) and passes through non-FW objects with a `no_input_chain` option. Skips rules that already have a chain assigned or have `Outbound` direction.

#### `NftNegation` — Transform

Converts element negation flags to `single_object_negation` flags for nftables' native `!=` operator. Unlike iptables (which needs temp chains for multi-object negation), nftables supports `!=` for both single and multi-object sets, so this processor simply converts all `src`/`dst`/`srv` negation flags directly — no chain splitting needed.

#### `SplitIfSrcAny` / `SplitIfDstAny` — Split

If Src/Dst is "any" (or has `single_object_negation` with a non-firewall object), creates an additional rule for the OUTPUT/INPUT chain. The original remains for FORWARD. First checks the `firewall_is_part_of_any_and_networks` option (per-rule then global) — if not set, passes the rule through unchanged.

#### `SplitIfSrcMatchesFw` / `SplitIfDstMatchesFw` — Split

Splits rules where the firewall object appears among other objects in Src/Dst. Each firewall occurrence gets its own rule.

#### `DecideOnChainIfDstFW` / `DecideOnChainIfSrcFW` — Transform

Sets chain to `input`/`output` if Dst/Src matches the firewall.

#### `SplitIfSrcFWNetwork` / `SplitIfDstFWNetwork` — Split

Splits when Src/Dst contains a network the firewall has an interface on. Creates an additional OUTPUT/INPUT rule.

#### `SpecialCaseWithFW2` — Transform

When Src == Dst == firewall, replaces both with the firewall's interface addresses (including loopback).

#### `DecideOnChainIfLoopback` — Transform/Split

Assigns `input`/`output` chain for any-any rules on loopback interface. For direction `Both`, splits into two rules.

#### `FinalizeChain` — Transform

Last-resort chain assignment. Defaults to `forward`, then upgrades to `input`/`output` based on direction and firewall match.

#### `DecideOnTarget` — Transform

Maps rule action to iptables-style target string (used internally; `PrintRule_nft` maps to nftables verdicts):

| Action | Target | Notes |
|--------|--------|-------|
| Accept | `ACCEPT` | |
| Deny | `DROP` | |
| Reject | `REJECT` | |
| Return | `RETURN` | |
| Continue | `.CONTINUE` | Pseudo-target — no verdict in output |
| Custom | `.CUSTOM` | |
| Accounting | — | Error: not yet supported by compiler |
| Branch | — | Error: not yet supported by compiler |
| Modify | — | Error: not yet supported by compiler |
| Pipe | — | Error: not yet supported by compiler |
| Scrub | — | Error: not supported in nftables |
| Skip | — | Error: not supported in nftables |

#### `RemoveFW` — Transform

Removes the firewall object from Src (if OUTPUT chain) or Dst (if INPUT chain) after chain assignment.

#### `ExpandMultipleAddresses` — Transform

Expands Host/Firewall objects in Src/Dst to their interface addresses via `compiler.expand_addr()`.

#### `GroupServicesByProtocol` — Split

Splits rules with services of different protocols. Special case: if only TCP+UDP with identical port sets, merges into `meta l4proto { tcp, udp } th dport ...` by setting `rule._extra['merged_tcp_udp'] = True`.

#### `Optimize3` — Filter

Removes duplicate rules that produce identical nftables commands. Includes the chain name in the dedup key (unlike iptables where the chain is part of the command string).

### NAT processors (`platforms/nftables/_nat_compiler.py`)

#### `DropRuleWithEmptyRE` — Filter

Drops rules where `_has_empty_re` is set (a required rule element became empty after upstream processing).

#### `EliminateDuplicatesInOSRC` / `EliminateDuplicatesInODST` / `EliminateDuplicatesInOSRV` — Transform

Removes duplicate objects within OSrc/ODst/OSrv by Python object identity.

#### `ClassifyNATRule` — Transform

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

#### `VerifyRules` — Validation

Aborts if negation is used in TSrc, TDst, or TSrv (these are not supported in translated elements).

#### `DecideOnChain` — Transform

Assigns NAT rules to chains:

| Rule type | Chain |
|-----------|-------|
| SNAT, SNetnat, Masq | `postrouting` |
| DNAT, DNetnat, Redirect | `prerouting` |
| NONAT, Return, SDNAT | no assignment needed |
| Other | Error: no chain assignment |

#### `GroupServicesByProtocol` — Split

Splits NAT rules with mixed-protocol services.

#### `ConvertToAtomicForAddresses` — Split

Creates the cartesian product of OSrc × ODst × TSrc × TDst. Each output rule has at most one object per element.

#### `AssignInterface` — Transform

Assigns outbound interface for SNAT/Masquerade rules. If TSrc is an interface on the firewall, uses that. Otherwise, creates one rule per non-loopback firewall interface.

### Print rule processors

#### `PrintRule_nft` (`platforms/nftables/_print_rule.py`) — Output

Final processor for policy rules. Generates nft rule statements and writes them to the per-chain `compiler.chain_rules` dict.

Rule format: `[iifname/oifname] [ip saddr] [ip daddr] [proto match] [ct state new] [log ...] [verdict]`

Key methods and their error reporting:

| Method | Errors reported |
|--------|----------------|
| `_print_addr(obj, rule)` | Dynamic interface not yet supported by compiler; Interface/Host has no addresses |
| `_print_addr_basic(obj, rule)` | Cannot resolve address for object type |
| `_print_src_addr()` / `_print_dst_addr()` | Could not resolve any source/destination addresses |
| `_print_service()` | Service type not yet supported by compiler |
| `_print_verdict()` | Custom chain jump not yet supported by compiler (warning) |
| `_print_reject()` | Unknown reject type, falling back to generic reject (warning) |

Supports:
- Interface matching: `iifname`/`oifname` (wildcard), `iif`/`oif` (loopback — index-based)
- Address matching: CIDR notation, address ranges (`start-end`), sets (`{ addr1, addr2 }`)
- Service matching: TCP/UDP ports (single, range, multiport sets), ICMP type/code, IP protocol number
- Merged TCP+UDP: `meta l4proto { tcp, udp } th dport ...`
- Connection tracking: `ct state new`
- Inline logging: `log prefix "..." level ...` combined with verdict
- Log prefix macros: `%N` (position), `%A` (action), `%I` (interface), `%C` (chain), `%R` (ruleset)

#### `NATPrintRule_nft` (`platforms/nftables/_nat_print_rule.py`) — Output

Final processor for NAT rules. Generates nft NAT rule statements.

Key methods and their error reporting:

| Method | Errors reported |
|--------|----------------|
| `_print_addr(obj, rule)` | Interface/Host has no addresses; Cannot resolve address for object type |
| `_print_service()` | Service type not yet supported by compiler |
| `_print_nat_action()` | DNAT has no translated destination; SDNAT not yet supported by compiler |

NAT action output:

| Rule type | Output |
|-----------|--------|
| NONAT | `accept` |
| Masq | `masquerade` |
| SNAT/SNetnat | `snat to addr[:port]` |
| DNAT/DNetnat | `dnat to addr[:port]` |
| Redirect | `redirect [to :port]` |
| Return | `return` |
| SDNAT | error — not yet supported |

### Compiler driver

`CompilerDriver_nft` (`platforms/nftables/_compiler_driver.py`) orchestrates
the full nftables compilation. The overall driver flow and the generated
script structure (`#!/usr/sbin/nft -f`, `flush ruleset`, `table inet
filter { … }`, `table ip nat { … }`) are documented in
[Compilation Pipeline](CompilationPipeline.md). Both iptables and nftables
drivers call `_warn_unsupported_options()` (base `CompilerDriver`) to emit
warnings for recognised but unimplemented firewall options (ULOG/NFLOG,
TCP/IP log options, numeric log levels, log_all, kernel timezone, bridge
interfaces). The nftables driver reuses the iptables routing compiler.

### Policy pipeline order

```
Begin → StoreAction → InterfaceAndDirection → SplitIfIfaceAndDirectionBoth →
EmptyGroupsInRE(src) → EmptyGroupsInRE(dst) → EmptyGroupsInRE(srv) → EmptyGroupsInRE(itf) →
ExpandGroups → DropRuleWithEmptyRE →
EliminateDuplicatesInSRC → EliminateDuplicatesInDST → EliminateDuplicatesInSRV →
FillActionOnReject → Logging_nft →
SplitIfSrcNegAndFw → SplitIfDstNegAndFw → NftNegation →
SplitIfSrcAny → SplitIfDstAny →
SplitIfSrcMatchesFw → SplitIfDstMatchesFw →
DecideOnChainIfDstFW → SplitIfSrcFWNetwork → DecideOnChainIfSrcFW →
SplitIfDstFWNetwork → SpecialCaseWithFW2 → DecideOnChainIfLoopback →
FinalizeChain → DecideOnTarget →
RemoveFW → ExpandMultipleAddresses → DropRuleWithEmptyRE →
[DropIPv4Rules OR DropIPv6Rules] → DropRuleWithEmptyRE →
ConvertToAtomicForInterfaces → GroupServicesByProtocol →
Optimize3 → [DetectShadowing (if check_shading)] →
PrintRule_nft → SimplePrintProgress
```

~35 processors vs. ~80 in iptables. The pipeline shares many base processors with iptables (`Begin`, `ExpandGroups`, `DropRuleWithEmptyRE`, `EliminateDuplicatesIn*`, `DropIPv4/6Rules`, `ConvertToAtomicForInterfaces`, `SimplePrintProgress`, `EmptyGroupsInRE`, `DetectShadowing`) but omits all mangle-table, temp-chain, and multiport processors. Negation is handled natively via `!=` (3 processors: `SplitIfSrcNegAndFw`, `SplitIfDstNegAndFw`, `NftNegation`). `SplitIfSrcAny`/`SplitIfDstAny` now check `firewall_is_part_of_any_and_networks` option with the same improved negation logic as iptables.

### NAT pipeline order

```
Begin → SingleObjectNegationItfInb → SingleObjectNegationItfOutb →
EmptyGroupsInRE(osrc) → EmptyGroupsInRE(odst) → EmptyGroupsInRE(osrv) →
EmptyGroupsInRE(tsrc) → EmptyGroupsInRE(tdst) → EmptyGroupsInRE(tsrv) →
ExpandGroups → DropRuleWithEmptyRE →
[DropIPv4Rules OR DropIPv6Rules] →
EliminateDuplicatesInOSRC → EliminateDuplicatesInODST → EliminateDuplicatesInOSRV →
ClassifyNATRule → VerifyRules →
SingleObjectNegationOSrc → SingleObjectNegationODst →
[SplitIfOSrcAny (if local_nat+fw_part_of_any)] →
[SplitIfOSrcMatchesFw (if local_nat)] →
LocalNATRule → DecideOnChain →
ReplaceFirewallObjectsTSrc →
ExpandMultipleAddresses → DropRuleWithEmptyRE →
[DropIPv4Rules OR DropIPv6Rules] → DropRuleWithEmptyRE →
GroupServicesByProtocol → ConvertToAtomicForAddresses →
AssignInterface → NATPrintRule_nft → SimplePrintProgress
```

### Not yet implemented

| Feature | nftables support | Notes |
|---------|-----------------|-------|
| IPv6 dual-stack (`inet` family) | Yes | Currently compiles separate `ip`/`ip6` passes |
| Dynamic interface addresses | Yes (via sets/maps) | No shell variable substitution like iptables |
| Inline logging with verdict | Partial | `log ... accept` works; LOG branching with multiple actions does not |
| Custom chain jump | Yes (`jump`/`goto`) | Warning emitted, `jump target` generated |
| Accounting (`counter`) | Yes (native) | Error emitted |
| Packet marking (`meta mark set`) | Yes | Error emitted for tagging option |
| Classification (`meta priority set`) | Yes | Error emitted for classification option |
| Policy routing (`fib`+marks) | Yes | Error emitted for routing option |
| Branch (sub-policy) | Yes (`jump`/`goto`) | Error emitted |
| SDNAT (simultaneous SNAT+DNAT) | Yes (two rules) | Error emitted |
| Pipe/QUEUE (`queue num`) | Yes | Error emitted |
| Shadowing detection | ✅ Done | `DetectShadowing` wired into policy pipeline (conditional on `check_shading` option) |
| Empty group validation | ✅ Done | `EmptyGroupsInRE` wired into both policy (SRC, DST, SRV, ITF) and NAT (OSRC, ODST, OSRV, TSRC, TDST, TSRV) pipelines |
| `firewall_is_part_of_any_and_networks` | ✅ Done | `SplitIfSrcAny`/`SplitIfDstAny` check this option |
| Negation expansion (policy) | ✅ Done | `NftNegation` + `SplitIfSrcNegAndFw` / `SplitIfDstNegAndFw` |
| NAT interface negation | ✅ Done | `SingleObjectNegationItfInb` / `SingleObjectNegationItfOutb` + `_print_interface()` `!=` output |
| NAT OSrc/ODst negation | ✅ Done | `SingleObjectNegationOSrc` / `SingleObjectNegationODst` set inline `!` flags |
| NAT local_nat | ✅ Done | `SplitIfOSrcAny` + `SplitIfOSrcMatchesFw` + `LocalNATRule` with nftables output chain |
| NAT ReplaceFirewallObjectsTSrc | ✅ Done | Replaces firewall in TSrc with interface facing ODst |
