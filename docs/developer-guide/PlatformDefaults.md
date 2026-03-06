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
| `nftables_supported` | (linux only) Whether the option is relevant for nftables |

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

`Host.get_option(key, default)` resolves an option value using a three-tier lookup:

1. **Explicit value** in `self.options[key]` (the JSON dict stored in the database).
2. **YAML default** from `platforms/<platform>/defaults.yaml` or `platforms/<os>/defaults.yaml`.
3. **Caller-supplied fallback** (the `default` argument).

This means the YAML files serve as runtime fallback for *every* `get_option()` call -- not just for seeding new objects. If a key is absent from the stored JSON, the YAML default is returned automatically. Compiler call sites no longer need to specify their own fallback values for options that have a YAML default; they can simply call `get_option('some_key')` and the YAML value will be used.

String values `"True"` / `"False"` (common in XML imports) are coerced to Python bools.


## The `placeholder` Field

Some options have an empty-string default (`''`) but the GUI should show a meaningful hint. For these, the YAML entry includes a `placeholder` field:

```yaml
  firewall_dir:
    type: 'str'
    default: ''
    placeholder: '/etc/fw'
    description: >-
      Directory on the firewall where the generated script will
      be stored.  Leave empty to use the default (/etc/fw).
```

The dialog's `_apply_placeholders()` method checks `placeholder` first, then falls back to `default`. This lets the GUI show a meaningful hint even when the stored default is an empty string.


## Adding a New Option

1. Add the entry to the appropriate `defaults.yaml` file (alphabetical order).
2. If it needs a GUI widget, add the widget to the `.ui` file and set the `widget` field.
3. The settings dialog will pick it up automatically via the YAML-driven widget maps.
4. The compiler reads the value via `get_option(key)` -- the YAML default is returned automatically if the option is absent from the stored JSON.


## JSON Remains the Storage Format

The `options` column still stores a JSON dict in the SQLite database. JSON holds the *user-set values*. The YAML files define the *schema and defaults*. If a key is absent from JSON, `get_option()` returns the YAML default automatically -- no extra logic needed at the call site.
