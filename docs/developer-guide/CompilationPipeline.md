# Compilation Pipeline

This document gives the big picture of how FirewallFabrik turns a firewall
definition (stored as `.fwf` / YAML, or imported from `.fwb` / XML) into an
executable shell script for iptables or nftables. Read this first; the
[Rule Processors](RuleProcessors.md) document drills into the individual
processor steps afterwards.

---

## Big picture

Every layer, its source files, and its role, in execution order:

```
========== INPUT ==========
  .fwf / YAML  or  .fwb / XML
  parsed by  core/_yaml_reader.py  /  core/_xml_reader.py
              |
              v
========== OBJECT MODEL ==========                  (SQLAlchemy, in-memory SQLite)
  core/_database.py     DatabaseManager: sessions, undo stack
  core/objects/*.py     Firewall, RuleSet, Rule, rule elements (STI models)
              |
              v
========== ORCHESTRATION ==========
  driver/_compiler_driver.py           base driver (shared)
  platforms/<p>/_compiler_driver.py    platform driver (iptables or nftables)
  Looks up firewall, loops address families, dispatches to sub-compilers,
  assembles the final script.
              |
              |  For each address family (IPv4, IPv6):
              v
========== PREPROCESSOR ==========
  platforms/linux/_preprocessor.py
  Normalises objects for the current address family.
              |
              v
========== RULE-PROCESSOR PIPELINE ==========
  Engine (platform-independent):
    compiler/_rule_processor.py    BasicRuleProcessor base class
    compiler/_compiler.py          Compiler: run_rule_processors() (pull-based)
    compiler/_comp_rule.py         CompRule: mutable working copy of a Rule

  Sub-compilers (a processor chain each):
    compiler/_nat_compiler.py            + platforms/<p>/_nat_compiler.py
    compiler/_policy_compiler.py         + platforms/<p>/_policy_compiler.py
    mangle pass                          iptables only, reuses policy compiler

  Processors in each chain come from:
    compiler/processors/_generic.py    shared: Begin, ExpandGroups, ...
    compiler/processors/_policy.py     policy base: InterfacePolicyRules, ...
    compiler/processors/_service.py    service separation: SeparateTCPWithFlags
    platforms/<p>/_policy_compiler.py  platform-specific policy processors
    platforms/<p>/_nat_compiler.py     platform-specific NAT processors

  Final processor is PrintRule: emits iptables / nft text.
              |
              v                                            (end of per-AF loop)
========== ROUTING ==========
  compiler/_routing_compiler.py
  Runs once per firewall, not per address family.
              |
              v
========== SCRIPT ASSEMBLY ==========
  driver/_configlet.py             loads template fragments
  driver/_jinja2_template.py       Jinja rendering
  resources/configlets/linux24/    prolog, reset, installer, epilog
              |
              v
========== OUTPUT ==========
  <firewall>.fw
  bash script (iptables)  or  nft -f script (nftables)
```

The key insight: the **compiler driver** is the orchestrator, the
**rule processors** inside each sub-compiler are the workers, and the
**configlets** provide the shell-script scaffolding around the generated
rules.

---

## End-to-end flow (iptables)

This walks through what happens when `fwf-ipt firewall1` (or the GUI
*Compile* action) is triggered.

1. **Driver startup** — `CompilerDriver_ipt.run(cluster_id, fw_id, …)` in
   `platforms/iptables/_compiler_driver.py`:

    - Open a DB session, look up the `Firewall` object.
    - Validate interface addresses, read firewall options, warn on
      unsupported options.
    - Build an `OSConfigurator_linux24` (handles `ip_forward`, kernel vars,
      module loading, …).
    - Gather all `Policy` and `NAT` rule sets for this firewall.
    - Decide IPv4 / IPv6 run order from the `ipv4_6_order` option.

2. **Per address family** (IPv4 first, then IPv6 by default):

    1. **Preprocessor** (`platforms/linux/_preprocessor.py`) — normalises
       objects for the selected address family.
    2. **NAT compilation** — instantiate `NATCompiler_ipt`, run its
       ~50-processor pipeline (see *iptables NAT pipeline order* in
       [RuleProcessors.md](RuleProcessors.md)). Output goes into the `*nat`
       table section.
    3. **Policy compilation** — instantiate `PolicyCompiler_ipt`, run its
       ~77-processor pipeline (see *Main compilation pass* in
       [RuleProcessors.md](RuleProcessors.md)). Output is split across the
       `*filter` and `*mangle` tables via `ipt_chain` on each rule.
    4. **Mangle pass** — a dedicated `PolicyCompiler_ipt` run for the
       mangle table (tagging / classify / routing).

3. **Routing pass** — `RoutingCompiler` runs once per firewall (not per
   address family). Produces `ip rule` / `ip route` statements.

4. **Script assembly** — `_assemble_script_skeleton()` loads configlet
   templates from `resources/configlets/linux24/` and renders the final
   shell script: shebang, header, prolog, `reset_all`, per-AF rule blocks,
   routing block, epilog, installer commands.

5. **Output** — written to `<firewall>.fw` in the working directory. The
   driver reports `Compiled successfully` or `Compiled with errors` and
   collects all warnings/errors in `all_errors` / `all_warnings`.

nftables follows the same shape, but simpler: no separate mangle pass
(native `meta mark set`), no temp-chain tricks (native `!=` for negation,
native sets for multiport), and fewer processors overall (~35 policy, ~30
NAT). The final script starts with `#!/usr/sbin/nft -f` and a
`flush ruleset`, then emits `table inet filter { chain input { … } … }`
blocks.

---

## Minimum you need to know to navigate the code

- If you're debugging **output correctness** (wrong iptables command, wrong
  chain, missing rule), start in the processor chain → see
  [RuleProcessors.md](RuleProcessors.md), particularly the *Full pipeline
  order* section.
- If you're debugging **script scaffolding** (wrong shebang, missing
  `reset_all`, broken installer), start in the platform
  `_compiler_driver.py` and the configlet templates under
  `resources/configlets/linux24/`.
- If you're debugging **input** (wrong rule in DB), start in the YAML /
  XML readers or in `core/objects/_rules.py`.
- For **per-rule tracing** through the processor chain, enable the `Debug`
  interceptor via `--xp` / `--xn` / `--xr` — see [Debugging](Debugging.md).

---

## Further reading

- [Rule Processors](RuleProcessors.md) — every processor, every pipeline,
  in execution order.
- [Database Manager](DatabaseManager.md) — how `core/_database.py` manages
  sessions and undo state.
- [Platform Defaults](PlatformDefaults.md) — where default option values
  live and how they flow into the compiler.
- [Debugging](Debugging.md) — how to trace a single rule through the
  pipeline.
- [Testing](Testing.md) — how the expected-output regression tests guard
  compiler output.
