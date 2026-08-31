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
| `inverted` | (bool only) Whether the checkbox has inverted semantics |
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

The list the editor offers is `PLATFORM_VERSIONS` in
`gui/platform_settings.py`: Firewall Builder's own list for iptables,
value for value, and for nftables the releases at which this compiler's
output changes - 0.9.3 for `meta hour` / `meta day` / `meta time` and
0.9.5 for `snat prefix to` / `dnat prefix to`.  Everything else the
nftables compiler emits is 0.8.2 or older.  Add a row to that list
whenever a new construct needs a release newer than one a supported
distribution ships, and a matching constant in
`platforms/nftables/_utils.py`.

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
