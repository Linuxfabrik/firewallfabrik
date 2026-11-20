# Rule Processor Developer Documentation

This document is the per-processor reference. For the surrounding
orchestration (driver, configlets, script assembly, end-to-end flow), see
[Compilation Pipeline](compilation-pipeline.md) first.

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

#### `printTotalNumberOfRules` (line 323 / 764) — Pass-through

Calls `slurp()` to buffer all upstream rules. If verbose mode is on, prints
" processing N rules". Returns `true` once (rules then drain from buffer),
`false` if no rules.

#### `createNewCompilerPass` (line 337 / 780) — Pass-through

Takes a `pass_name` constructor parameter. Calls `slurp()`, prints the pass
name, and returns `true`. Creates a logical boundary between compilation
phases — all rules are buffered and then re-released.

#### `simplePrintProgress` (line 349 / 838) — Pass-through

Pulls one rule at a time. If the rule's label differs from the previous one,
prints " rule LABEL" (when verbose). Pushes the rule unchanged.

#### `singleRuleFilter` (line 631 / 818) — Filter

Used in single-rule compilation mode (`-xp`). Pulls each rule and checks:
- If not in `single_rule_mode`: pushes rule through unchanged.
- If in `single_rule_mode`: only pushes rules whose ruleset name matches
  `single_rule_ruleset_name` AND whose position matches `single_rule_position`.
  Other rules are silently dropped.

Always returns `true` (even when dropping) to keep pulling upstream.

#### `Debug` (line 621 / 791) — Pass-through

Calls `slurp()` to buffer all upstream rules. When `rule_debug_on` is true,
prints a separator line with the **previous** processor's name, then for each
rule matching `debug_rule`, calls `debugPrintRule()`. Automatically inserted
after every processor by `Compiler::add()` when `-xp` is active (except after
`simplePrintProgress`).

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

#### `checkForObjectsWithErrors` (line 594 / 1411) — Validation

Pulls one rule and iterates all rule elements. For each object that has a
`.rule_error` attribute set to `true`, calls `compiler->abort()` with the
object's `.error_msg`. This propagates errors from MultiAddress objects that
failed DNS resolution or other preprocessor steps.

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

#### `singleObjectNegation` (line 376 / 985) — Transform

Optimizes negation when a rule element has `getNeg() == true` and exactly
one object. Instead of the expensive chain-based negation expansion, sets
the `single_object_negation` boolean attribute on the rule and clears the
negation flag. This lets `PrintRule` emit a simple `!` prefix.

For interface elements (`Itf`, `ItfInb`, `ItfOutb`): always applies.

For address elements: only applies when the single address has exactly one
inet address AND doesn't `complexMatch()` the firewall (which would need
splitting first).

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

#### `replaceClusterInterfaceInItfRE` (line 402 / 1102) — Transform

For each interface in the rule element that belongs to a failover cluster:

1. Looks up the `FailoverClusterGroup`.
2. Calls `getInterfaceForMemberFirewall()` to find the real member interface.
3. Replaces the cluster interface reference with the real interface.
4. Sorts the element by name for deterministic output.

Must run **before** `ItfNegation` (which needs real interfaces).

#### `eliminateDuplicatesInRE` (line 434 / 1148) — Transform

Removes duplicate objects within a rule element. Iterates through the
element, keeping only the first occurrence of each object (compared by ID
via the `equalObj` functor, or a custom comparator). If duplicates were
removed, clears and rebuilds the element with unique objects only.

#### `recursiveGroupsInRE` (line 450 / 1204) — Validation

For each group object in the rule element, recursively checks all children
for circular references (a group containing itself, directly or indirectly).
Aborts compilation with an error if recursion is detected.

#### `emptyGroupsInRE` (line 470 / 1258) — Filter/Transform

Detects groups with zero non-group children (recursively counted via
`countChildren()`). Behavior depends on the `ignore_empty_groups` firewall
option:

- **If true**: removes the empty groups and issues a warning. If the rule
  element becomes "any" after removal, **drops the entire rule** with a
  warning (a match-nothing element is meaningless).
- **If false**: aborts compilation with an error listing the empty groups.

#### `swapMultiAddressObjectsInRE` (line 486 / 1340) — Transform

Replaces compile-time `MultiAddress` objects (where `isRunTime() == true`)
with their `MultiAddressRunTime` equivalents. Generates a stable ID by
appending `"_runtime"` to the original object's string ID. Looks up or
creates the runtime object in `dbcopy`. This allows platform-specific
handling of DNS names and other dynamic address types.

#### `expandMultipleAddressesInRE` (line 499 / 1401) — Transform

Replaces Host and Firewall objects in a rule element with their individual
interface addresses. Calls `compiler->_expand_addr()` which:

1. Recursively expands address objects via `_expand_addr_recursive()`.
2. Skips loopback interfaces (unless the rule is attached to loopback).
3. Skips bridge ports.
4. Expands failover cluster interfaces to corresponding member interfaces.
5. Filters by current address family (IPv4 vs. IPv6).
6. Sorts results by address value for deterministic output.

#### `ReplaceFirewallObjectWithSelfInRE` (line 858 / 915) — Transform

Replaces explicit firewall object references with a `DNSName` object named
`"self"` (source name `"self"`). This is used by platforms that support
runtime self-identification. Looks up or creates the runtime DNSName in
`dbcopy`. Should run after `splitIfSrc/DstMatchesFw` to ensure the firewall
is isolated in its own rule.

#### `replaceFailoverInterfaceInRE` (line 606 / 1440) — Transform

Replaces cluster failover interfaces with real member interfaces. Handles
both interfaces where `isFailoverInterface() == true` and those with the
`cluster_interface` option set. For each, looks up the `FailoverClusterGroup`
and gets the corresponding member interface via
`getInterfaceForMemberFirewall()`.

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

#### `ExpandGroups` (line 160 / 414) — Transform

Recursively expands all group objects in **Src, Dst, and Srv**. Calls
`compiler->expandGroupsInRuleElement()` for each, which:

1. Recursively replaces group references with their member objects.
2. Skips `MultiAddressRunTime` objects (already handled).
3. Checks address family compatibility.
4. Sorts results alphabetically by name.
5. Validates each expanded object is appropriate for the element type.

#### `expandGroupsInSrv` (line 165 / 431) — Transform

Same as `ExpandGroups` but only for the **Srv** element.

#### `expandGroupsInItf` (line 170 / 440) — Transform

Same as `ExpandGroups` but only for the **Itf** element.

#### `ExpandMultipleAddresses` (line 277) — Transform

Expands Host and Firewall objects in both **Src and Dst** to their
individual interface addresses. Calls `compiler->_expand_addr()` on each.

#### `addressRanges` (line 283 / 472) — Split

Expands `AddressRange` objects in Src and Dst to equivalent network objects:

- **IPv4 ranges**: converted to a set of networks via `convertAddressRange()`.
- **IPv6 ranges**: kept as-is (iptables supports `-m iprange` for IPv6).

Creates `Network` objects for each converted address and registers them
with `group_registry` if present.

#### `checkForZeroAddr` (line 407 / 673) — Validation

Detects likely configuration errors:

1. `findHostWithNoInterfaces()` — finds Host objects with no Interface children
   (can't have an address).
2. `findZeroAddress()` — finds Address/Network/Host with address 0.0.0.0.
   Skips the "any" object, dynamic interfaces, unnumbered interfaces, and
   bridge ports. Also catches the pattern A.B.C.D/0 where A.B.C.D ≠ 0.0.0.0
   (likely a /32 vs. /0 typo).

Aborts compilation if any are found.

#### `checkForUnnumbered` (line 299 / 718) — Validation

Calls `compiler->catchUnnumberedIfaceInRE()` on Src and Dst. Aborts if any
interface is unnumbered or a bridge port (these can't be used as addresses
in rules).

#### `ConvertToAtomicForAddresses` (line 310 / 733) — Split

Creates the **cartesian product** of Src × Dst. For each (src_obj, dst_obj)
pair, creates a new rule with exactly one object in Src and one in Dst.
Srv is left unchanged (may still have multiple objects).

#### `ConvertToAtomicForIntervals` (line 316 / 762) — Split

Splits rules so each has exactly one `Interval` object. If the Interval
element is "any" or missing, pushes the rule unchanged. Otherwise creates
one rule per interval.

#### `ConvertToAtomic` (line 321 / 790) — Split

Full atomic conversion: creates the **cartesian product** of Src × Dst × Srv.
Each output rule has exactly one object in each element. Used in the
shadowing detection pass where exact comparison is needed.

#### `MACFiltering` (line 509 / 980) — Transform

Removes `physAddress` objects from Src and Dst (MAC filtering is unsupported
on most platforms). Issues a warning if any were removed. Aborts if a rule
element becomes empty after removal (means the rule only matched on MAC).

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

### Generic service processors

These processors operate on the Srv (or OSrv for NAT) rule element.

> *C++ reference: `Compiler.h` / `Compiler.cpp`*

#### `groupServicesByProtocol` (line 655) — Split

Inherits from `groupServices`, which splits rules with multiple services into
groups based on a virtual `groupingCode()`. For `groupServicesByProtocol`,
the grouping code is `srv->getProtocolNumber()`. Result: each output rule
has services of the same protocol.

If the rule has only one service, it passes through unchanged.

#### `separateTCPWithFlags` — Split

Inherits from `separateServiceObject`. Separates TCP services that have TCP
flags set into individual rules. Condition: `TCPService::isA(srv) && has flags`.

#### `separatePortRanges` — Split

Separates TCP/UDP services where source and destination port ranges are
mismatched (can't be combined in a single `-m multiport` match).

#### `separateSrcPort` — Split

Separates TCP/UDP services that have source port specifications into
individual rules (source ports need separate `--sport` matches).

#### `separateUserServices` — Split

Separates `UserService` objects (iptables `--uid-owner` match) into
individual rules (only valid in OUTPUT chain).

#### `verifyCustomServices` — Validation

For each `CustomService` in the Srv element, checks that
`getCodeForPlatform(compiler->myPlatformName())` is non-empty. Throws
`FWException` if a custom service has no code for the target platform.

#### `CheckForTCPEstablished` — Validation

Aborts if any `TCPService` in Srv has `getEstablished() == true` (the
"established" flag is not supported by the iptables platform — stateful
matching is done via conntrack instead).

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
| `replaceClusterInterfaceInItf` | `replaceClusterInterfaceInItfRE` | Itf | ✅ `compiler/processors/_generic.py` |

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
new_rule.src = [object]  # set single object
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
