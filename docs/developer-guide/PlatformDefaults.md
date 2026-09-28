# Platform and OS Defaults (Single Source of Truth)

## Problem

Firewall and host OS options are stored as a JSON dict in the SQLAlchemy `options` column. Because JSON is schema-free, there was no single authoritative place that defined which keys exist, what types they have, or what their default values are. Defaults were scattered across:

* Hardcoded Python dicts in GUI dialog files
* ORM model defaults
* Implicit assumptions in the compiler

This led to:

* **Silent failures from typos** -- a misspelled key (e.g. `log_perfix` instead of `log_prefix`) would be stored without error but silently ignored by the compiler.
* **Inconsistent defaults** -- the GUI, the compiler, and new-object creation could each assume a different default for the same option.
* **No visible defaults in the GUI** -- text fields showed no placeholder text indicating what the compiler would use if left empty.
* **No tooltips** -- users had to guess what each setting does.


## Solution

All option definitions now live in YAML files co-located with the platform packages:

```
src/firewallfabrik/platforms/
    iptables/defaults.yaml    # 47 options
    nftables/defaults.yaml    # 49 options
    linux/defaults.yaml       # 33 host OS options
```

Each option entry contains:

| Field | Purpose |
|---|---|
| `type` | Data type: `bool`, `str`, `int`, `enum`, `text`, `tristate` |
| `default` | The canonical default value (used for seeding new objects and GUI population) |
| `supported` | Whether the compiler uses this option (`true`/`false`) |
| `widget` | Name of the Qt widget in the `.ui` file (or `~` for options without a widget) |
| `placeholder` | (str only) Placeholder text for the GUI when `default` is empty |
| `description` | Human-readable description, used as GUI tooltip |
| `values` | (enum only) List of allowed values |
| `label` | (linux only) Associated QLabel widget name, for disabling |
| `nftables_supported` | (linux only) Whether the option is relevant for nftables — the editor greys the field out when it is false, so it has to be true for anything the generated nftables script uses |

Example from `nftables/defaults.yaml`:

```yaml
  log_prefix:
    type: 'str'
    default: 'RULE %N -- %A '
    supported: true
    widget: 'logprefix'
    description: >-
      Prefix string for log messages.  Supported macros:
      %N = rule number, %A = action, %I = interface name,
      %C = chain name, %R = rule set name.
```


## Loader API

The module `firewallfabrik.platforms._defaults` provides cached access to the YAML schemas:

| Function | Returns |
|---|---|
| `get_platform_defaults(platform)` | Full schema dict for a compiler platform (`iptables` or `nftables`) |
| `get_os_defaults(os_name)` | Full schema dict for a host OS (e.g. `linux24`) |
| `get_default_values(platform)` | `{key: default}` for supported options only -- used to seed new firewall objects |
| `get_os_default_values(os_name)` | `{key: default}` for supported OS options |
| `get_option_default(platform, os_name, key)` | Single option default, checking platform then OS |
| `get_known_keys(platform, os_name)` | Set of all valid option keys |
| `validate_options(platform, os_name, options)` | List of warnings for unknown keys in an options dict |

YAML files are loaded once via `@functools.cache` and `importlib.resources`.


## How Defaults Flow Through the System

### 1. New Object Creation

When a new Firewall is created (`new_device_dialog.py`), `get_default_values(platform)` seeds the initial `options` dict with all supported defaults. This dict is stored as JSON in the database.

### 2. GUI Settings Dialogs

The settings dialogs (`iptables_settings_dialog.py`, `nftables_settings_dialog.py`, `linux_settings_dialog.py`) load the YAML schema at import time and use it for:

* **Widget mapping** -- which widget corresponds to which canonical option key
* **Tooltips** -- `entry['description']` is set via `setToolTip()`
* **Placeholder text** -- `entry['placeholder']` or `entry['default']` is shown as grey text in `QLineEdit` fields
* **Unsupported marking** -- widgets for `supported: false` options are disabled
* **Populate fallback** -- if an option is missing from the stored JSON, the YAML default is used for populating the dialog

### 3. Compiler / ORM (`get_option()`)

`Host.get_option(key)` resolves an option value using a two-tier lookup:

1. **Explicit value** in `self.options[key]` (the JSON dict stored in the database).
2. **YAML default** from `platforms/<platform>/defaults.yaml` or `platforms/<os>/defaults.yaml`.

If the key is not found in either tier, `get_option()` raises a **`KeyError`**. This catches typos in compiler code (e.g. `get_option('acept_established')`) at the earliest possible moment -- the first test run will fail with a clear error message instead of silently returning `None`.

The method accepts **no caller-supplied fallback**. All defaults live in the YAML files. Compiler call sites simply call `fw.get_option('some_key')` without a second argument.

The second argument it *does* take is a **platform**, and only a driver passes it. `get_option()` resolves the schema through `fw.platform`, and a firewall imported from a `.fwb` file says `iptables` whatever it is compiled with, because Firewall Builder has no other Linux platform. `CompilerDriver.firewall_option(fw, key)` names the platform the driver compiles for, so the nftables driver reads the nftables schema. Read a firewall option in a driver through that method and nowhere else: `fw.options.get(key, something)` puts a second default beside the one in the YAML file, and the two drift.

A boolean is compared after every whitespace character is removed from it, the way `FWObject::getBool` does it (`firewallfabrik.core._options.option_is_true`). A data file may write the value on a line of its own, and `'\n True \n' == 'true'` is False while `bool('\n False \n')` is True - so without the removal the same file answers the same question both ways. The removal belongs to the boolean test alone: a log prefix ends in a space on purpose.

> **Note**: `rule.get_option(key, default)` on `CompRule` objects is a *different method* that still accepts a caller-supplied default, because rules have their own per-rule options dict and no YAML schema.

String values `"True"` / `"False"` (common in XML imports) are coerced to Python bools.


## Zero Is Not Always a Value

Four host OS options are numbers whose default is `-1`, meaning "leave the
kernel setting alone": `linux24_conntrack_max`,
`linux24_conntrack_hashsize`, `linux24_tcp_fin_timeout` and
`linux24_tcp_keepalive_interval`. A stored `0` means the same thing, and
the OS configurator maps it to `-1` before it decides whether to emit the
line at all. Firewall Builder does the same and says why above the two
conntrack ones (`OSConfigurator_linux24.cpp`), because every `.fwb` it
writes carries `0` for a field the administrator left alone.

The mapping is load-bearing, not cosmetic. `nf_conntrack_max` of 0 makes
`ct_count > nf_conntrack_max` true for every new connection
(`net/netfilter/nf_conntrack_core.c`), so the box logs "table full,
dropping packet" and stops passing traffic; `nf_conntrack_hash_resize`
answers 0 with `-EINVAL`; `tcp_fin_timeout` of 0 ends a connection before
it can close in order.

The spin boxes in `linuxsettingsdialog_q.ui` therefore start at `-1` and
show "kernel default" there. A field whose default the editor cannot show
turns that default into whatever its minimum happens to be on the next
save, which is how the zero got into the data files in the first place.

## The Release a Firewall Is Compiled For

The `version` field on the firewall object is not an option and lives
beside `platform` and `host_OS` in the object's `data`, not in `options`.
It says which release of the packet filter the generated script has to
work on, and both compilers gate parts of their output on it.

**A release belongs to the platform the firewall names.**  Firewall
Builder says so by taking the platform as the argument of
`getVersionsForPlatform` (libgui/platforms.cpp:418), and both
`get_iptables_version` and `get_nftables_version` ask it before they read
the field: `lt_1.2.6` is an iptables release and `0.9.3` an nftables one,
and each is below every gate of the *other* platform, so reading it there
would silently take away every version-gated match.  Either compiler can
be handed either firewall - the CLI takes the platform from the command
it was called as, and the audit corpus compiles every firewall for both.

**An empty value means the newest.**  Without a pinned release the target
is whatever the machine runs, which for every currently supported
distribution is iptables 1.8.x and nftables 1.x.  Firewall Builder reads
the empty value as the *oldest* instead (`version_compare("", ...)` is
negative and its pipeline switches on it), which is why its reference
output writes an address range out as covering networks where fwf uses
`-m iprange`.  That difference is deliberate and accounts for a large
part of the `missing` column in `compare-reference.sh`.

The list the editor offers lives in `platforms/_versions.py`, beside the
compilers, newest first.  Each entry is one range of releases between two
gates - "1.0.0 to 1.0.8", "0.9.5 to 0.9.8" - so that exactly one entry is
right for a machine, and only the top one is open upwards ("1.0.9+",
"1.6.2+").  There is no "or later" below it and no "any": an entry below
the machine's release loads there as well, but leaves out, and reports,
every rule that needs more - on a Deny rule that is a firewall letting
through what it should stop - and "any" read as "fits every machine" when
it meant "the newest".  A new firewall stores the top entry's value; one
that names none (an imported `.fwb`, an older data file) is shown as "not
set", compiled for the top entry, and the driver warns about it.
`DEFAULT_IPTABLES_VERSION` and `DEFAULT_NFTABLES_VERSION` are derived from
the top entry, and `tests/test_platform_versions.py` fails when a compiler
gains a gate the list has no entry for.

The stored value of an entry is the first release of its range, which
keeps every value Firewall Builder wrote readable.  `ge_1.2.6` is the one
without an entry: the comparison reads it as 0.2.6, below every gate, so
it never compiled as "1.2.6 to 1.2.8", and the combo shows it as the value
it is.

The nftables gates are 0.9.1 (`flags dynamic`, the name of a standard
chain priority, `ct count` and `limit` in a set), 0.9.2 (`ip option`, the
inet route chain), 0.9.3 (`meta hour` / `day` / `time`), 0.9.5
(`snat` / `dnat prefix to`), 0.9.9 (the `tcp flags syn / syn,rst,ack`
notation), 1.0.0 (`reject with icmp <code>` without `type`) and 1.0.9
(`priority dstnat` on the output hook).  Below each of them the compiler
writes the older spelling, or reports the rule and leaves it out where
there is none.  The iptables gates are the checks of the iptables
compiler, from 1.2.6 to 1.6.2, and the upper end of each range is the last
release before the next gate (netfilter iptables tags).

A kernel feature is gated at the first nftables release after the kernel
that brought it - a proxy, since the entry names nftables and not the
kernel.  RHEL 8 is the exception, and it is handled by which entry it
takes, not by a gate: its 4.18 kernel refuses `ip option` and `meta hour`
at every point release, and `ct count` and `limit` in a set before kernel
build 4.18.0-359 ("nf_tables: add elements with stateful expressions" and
its series in the kernel changelog), which RHEL 8.6 is the first to ship.
So RHEL 8.0 to 8.5 take 0.9.0 and RHEL 8.6 to 8.10 take 0.9.1, whether
they run nftables 0.9.3 or, from 8.9, 1.0.4.

Each label names the distributions its entry is right for, in the label
itself ("0.9.[5-8] (rhel9.0 debian11 leap15.5)"), because a tooltip is too
slow to wait for while picking; "+" on a distribution means that release
and every later one measured.  "Lookup Version ..." beside the list logs
in the way the installer does - management address, user and ssh
arguments from the firewall's installer settings, a key or the agent
first and a password only when that is not enough - and reads `nft
--version`, `iptables --version`, `uname -r` and /etc/os-release
(`gui/version_lookup.py`).  `_versions.entry_for` then takes the newest
entry whose first release is not newer than the installed one, and places
RHEL 8 by its kernel build rather than by its point release, because an
early rebuild names none (Rocky Linux 8.3 has `VERSION_ID="8"`).

Which entry each distribution takes was
measured by compiling the corpus for the entry and loading it with
`tools/compiler-audit/load-nft.sh` (nftables) or replaying it with
`replay-iptables.sh` (iptables) on a linked clone of each distribution -
once as the template came, once fully updated - and, for RHEL, by booting
the kernel and installing the nftables of each point release from the
Rocky vault, whose repositories also gave the releases per point release:

| Distribution | nftables, kernel | nftables entry |
|---|---|---|
| RHEL 8.0 to 8.5 | 0.9.0 to 0.9.3, 4.18.0-80 to -348 | 0.9.0 |
| RHEL 8.6 to 8.8 | 0.9.3, 4.18.0-372 to -477 | 0.9.1 |
| RHEL 8.9, 8.10 | 1.0.4, 4.18.0-513, -553 | 0.9.1 |
| RHEL 9.0 | 0.9.8, 5.14.0-70 | 0.9.5 to 0.9.8 |
| RHEL 9.1 to 9.3 | 1.0.4, 5.14.0-162 to -362 | 1.0.0 to 1.0.8 |
| RHEL 9.4 to 9.8 | 1.0.9, 5.14.0-427 to -687 | 1.0.9+ |
| RHEL 10.0 to 10.2 | 1.1.1 to 1.1.5, 6.12 | 1.0.9+ |
| Debian 11 | 0.9.8, 5.10 | 0.9.5 to 0.9.8 |
| Debian 12 | 1.0.6, 6.1 | 1.0.0 to 1.0.8 |
| Debian 13 | 1.1.3, 6.12 | 1.0.9+ |
| Fedora 44 | 1.1.6, 6.19 to 7.2 | 1.0.9+ |
| openSUSE Leap 15.5 | 0.9.8, 5.14 | 0.9.5 to 0.9.8 |
| openSUSE Leap 16.0 | 1.1.3, 6.12 | 1.0.9+ |
| Ubuntu 22.04 | 1.0.2, 5.15 | 1.0.0 to 1.0.8 |
| Ubuntu 24.04 | 1.0.9, 6.8 | 1.0.9+ |
| Ubuntu 26.04 | 1.1.6, 7.0 | 1.0.9+ |

Measured points: RHEL 8.3, 8.5, 8.6 and 8.10, 9.0, 9.1, 9.4 and 9.8,
10.0 and 10.2.  RHEL 8.0 to 8.2 were not loaded; their releases come from
the CentOS vault (kernel 4.18.0-80 to -193, nftables 0.9.0 and 0.9.3), and
they are listed with 8.5 because their kernel predates the same backport.
All of them ship iptables 1.8 (1.8.2 on RHEL 8.0 up to 1.8.11), which is
the "1.6.2+" iptables entry.  The RHEL kernels are built without the time
match (`# CONFIG_NETFILTER_XT_MATCH_TIME is not set` in the kernel config
of 8.10, 9.8 and 10.2), so an iptables rule with a time window fails there
whatever release is picked.  iptables 1.8.5 (RHEL 8) also refused an
SNAT port range starting at 0 (`--to-source 198.51.100.1:0-1024`), which
1.8.7 and later took.  Beyond those two the replay showed only what an
unprivileged namespace or an unresolvable DNS name causes.  The nftables
`meta time` is part of nf_tables and loads on RHEL.

A rate limit kept per key is written as a set of the table declared
`flags dynamic,timeout` that the rule updates, not as a `meter`, on every
release: before nftables 1.1.0 a meter is an anonymous set without the
timeout flag, which the kernel refuses with EOPNOTSUPP, and a second rule
naming the same meter fails with EBUSY.

## The `placeholder` Field

Some options have an empty-string default (`''`) but the GUI should show a meaningful hint. For these, the YAML entry includes a `placeholder` field:

```yaml
  linux24_path_iptables:
    type: 'str'
    default: ''
    placeholder: '/sbin/iptables'
    description: >-
      Path to the iptables binary.
      Leave empty to use the compiler default.
```

The dialog's `_apply_placeholders()` method checks `placeholder` first, then falls back to `default`. This lets the GUI show a meaningful hint even when the stored default is an empty string.

> **Important**: Only use `placeholder` for options where an empty string genuinely means "use the compiler's built-in logic" (e.g. tool paths, where the compiler has its own `DEFAULT_TOOL_PATHS` dict). For options where the default is a concrete value, set `default` directly -- do **not** leave `default` empty and hide the real value in a Python `or` fallback.


## Adding a New Option

1. Add the entry to the appropriate `defaults.yaml` file (alphabetical order). If both platforms have the option, give it the **same** default in both: the same option means the same thing on either, and a firewall switched from one to the other must not change what its script does. `tests/test_option_defaults_are_the_only_defaults.py` asserts that, and that no driver reads such a key out of the raw options dict.
2. If it needs a GUI widget, add the widget to the `.ui` file and set the `widget` field.
3. The settings dialog will pick it up automatically via the YAML-driven widget maps.
4. The compiler reads the value via `fw.get_option('key')` -- the YAML default is returned automatically if the option is absent from the stored JSON. If you forget to add the YAML entry, `get_option()` raises `KeyError` immediately.


## JSON Remains the Storage Format

The `options` column still stores a JSON dict in the SQLite database. JSON holds the *user-set values*. The YAML files define the *schema and defaults*. If a key is absent from JSON, `get_option()` returns the YAML default automatically. If the key is absent from both JSON and YAML, `get_option()` raises `KeyError` -- there is no silent fallback to `None`.
