# Debugging the Compiler Pipeline

Both the Python `fwf-ipt` and the C++ `fwb_ipt` compilers support per-rule debugging. When enabled, a `Debug` interceptor is automatically inserted after every processor in the pipeline, printing the state of the specified rule after each transformation step.

## CLI Flags

| Flag | Argument | Purpose |
|------|----------|---------|
| `-xp` / `--xp` | rule position (int) | Debug a **policy** rule |
| `-xn` / `--xn` | rule position (int) | Debug a **NAT** rule |
| `-xr` / `--xr` | rule position (int) | Debug a **routing** rule |

The rule position corresponds to the rule's position number as shown in the GUI (0-indexed).

Debug output goes to **stderr**.

## Python (`fwf-ipt`)

```bash
# Debug policy rule 10 of firewall 001-p-billing01
fwf-ipt \
    --file ~/git/lf/gitlab/001/fw/001.fwb \
    -d /tmp/ \
    --xp 10 \
    001-p-billing01 \
    2>fwf_debug.txt

# Debug NAT rule 3
fwf-ipt \
    --file ~/git/lf/gitlab/001/fw/001.fwb \
    -d /tmp/ \
    --xn 3 \
    001-p-fw01 \
    2>fwf_nat_debug.txt

# Debug routing rule 0
fwf-ipt \
    --file ~/git/lf/gitlab/001/fw/001.fwb \
    -d /tmp/ \
    --xr 0 \
    001-p-fw01 \
    2>fwf_routing_debug.txt
```

## C++ (`fwb_ipt`)

```bash
# Debug policy rule 10 of firewall 001-p-billing01
fwb_ipt \
    -f ~/git/lf/gitlab/001/fw/001.fwb \
    -d /tmp/ \
    -xp 10 \
    001-p-billing01 \
    2>cpp_debug.txt

# Debug NAT rule 3
fwb_ipt \
    -f ~/git/lf/gitlab/001/fw/001.fwb \
    -d /tmp/ \
    -xn 3 \
    001-p-fw01 \
    2>cpp_nat_debug.txt

# Debug routing rule 0
fwb_ipt \
    -f ~/git/lf/gitlab/001/fw/001.fwb \
    -d /tmp/ \
    -xr 0 \
    001-p-fw01 \
    2>cpp_routing_debug.txt
```

**Note:** The C++ binary uses single-dash flags (`-xp`, `-xn`, `-xr`) while the Python CLI accepts both single-dash and double-dash (`--xp`, `--xn`, `--xr`).

## Debug Output Format

Both compilers produce the same format — a separator line with the processor name, followed by the rule state:

```
--- processor name -----------------------------------------------------------
10 (eth0)         001-p-billing01               Any        smtp    eth0        1        2
                                                      smtps 587
                                                          imaps
 pos=10 c=OUTPUT t=ACCEPT .iface=eth0
```

The columns show:
- **Label**: rule position and interface label (e.g. `10 (eth0)`)
- **Src**: source objects (or `Any`)
- **Dst**: destination objects (or `Any`)
- **Srv**: service objects with ports
- **Itf**: interface objects
- **Direction**: `1` = Inbound, `2` = Outbound, `0` = Both
- **Action**: `1` = Accept, `2` = Deny, etc.
- **Metadata line**: `pos=` position, `c=` chain, `t=` target, `.iface=` assigned interface, plus any extra flags

## Cross-Compiler Comparison

To identify which processor produces different results between Python and C++:

```bash
# Run both with the same --xp flag
fwf-ipt \
    --file ~/git/lf/gitlab/001/fw/001.fwb \
    -d /tmp/ --xp 10 001-p-billing01 2>fwf_debug.txt

fwb_ipt \
    -f ~/git/lf/gitlab/001/fw/001.fwb \
    -d /tmp/ -xp 10 001-p-billing01 2>cpp_debug.txt

# Diff the traces — first divergence reveals the buggy processor
diff --unified fwf_debug.txt cpp_debug.txt
```

## How It Works

When any `-xp`/`-xn`/`-xr` flag is set:

1. `CompilerDriver` sets `rule_debug_on = True` and stores the rule position in `debug_rule_policy` / `debug_rule_nat` / `debug_rule_routing`.
2. The compiler's `add()` method automatically inserts a `Debug` processor after every real processor (except `SimplePrintProgress`).
3. Each `Debug` processor uses `slurp()` to buffer all upstream rules, prints a separator with the **previous** processor's name, then calls `compiler.debug_print_rule(rule)` for rules matching the debug position.
4. `PolicyCompiler_ipt` overrides `debug_print_rule()` with a rich columnar format showing src/dst/srv/itf with negation prefixes, chain, target, and metadata flags.

### Source locations

- **Python**: `_rule_processor.py:Debug`, `_compiler.py:add()`, `_policy_compiler.py:debug_print_rule()`
- **C++**: `Compiler.h:621` (`Debug` class), `Compiler.cpp:691` (`add()`), `PolicyCompiler_ipt.cpp:4695` (`debugPrintRule()`)

## Why the Compilers Don't Use Python's `logging` Library

The compilers use their own `self.warning()` / `self.abort()` / `self.error()` methods (defined in `_base.py:BaseCompiler`) instead of the standard `logging` module. These methods do more than just print messages:

- **Per-rule tracking** — warnings and errors are stored per rule label, so they can be embedded as inline comments in the generated firewall script.
- **Compiler status flags** — calling `warning()` sets the compiler status to `FWCOMPILER_WARNING`; `abort()` sets `_aborted = True` and halts compilation.
- **Matches the C++ architecture** — the original C++ Firewall Builder uses the same pattern (`Compiler::warning()`, `Compiler::abort()`), keeping the Python port consistent.

The `logging` module cannot provide per-rule tracking or status flag management, so it should not be used inside compiler code.
