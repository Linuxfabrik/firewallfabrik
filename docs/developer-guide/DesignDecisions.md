# Design Decisions

## PySide6 vs. PyQt6

There is no strong technical reason to prefer PySide6 over PyQt6 for this project -- both frameworks are perfectly suitable. We chose PySide6 primarily because FirewallFabrik is being ported from the original Firewall Builder C++/Qt codebase. PySide6's API closely mirrors C++ Qt, which makes the porting process more straightforward and keeps the Python code visually and structurally similar to the original implementation.

Additionally, PySide6 is licensed under the LGPL, which is more permissive and leaves the door open for potential proprietary extensions in the future.


## Removal of the "Deleted Objects" Feature from Firewall Builder

In Firewall Builder, deleting an object does not remove it permanently. Instead, the object is moved to a special system library called "Deleted Objects" (`sysid99` / `FWObjectDatabase::DELETED_OBJECTS_ID`). This is implemented in `ObjectManipulator::deleteObject()` (`ObjectManipulator_ops.cpp`) and `FWCmdMoveObject` (`FWCmdMoveObject.cpp`). The idea is that users can later browse this library and restore objects.

However, the feature provides only very limited value in practice. When an object is moved to "Deleted Objects", all references to it are removed immediately: every rule element, group membership, or other relationship pointing to the object is cleaned up (and rule elements left empty are filled with dummy placeholders like `dummySource` or `dummyDestination`). The deleted references are stored in a `reference_holders` map inside the `FWCmdMoveObject` undo command, so pressing **Ctrl+Z (undo) within the same session** correctly restores both the object and all its references.

The problem is that the `reference_holders` map only lives in the in-memory undo stack. It is **not** persisted to the `.fwb` file. Once the user saves, closes, and reopens the file, the undo history is gone. At that point, the only way to restore an object from "Deleted Objects" is the right-click "Move to ..." or "Undelete" menu action -- and both `undeleteLibrary()` (`ObjectManipulator_slots.cpp:71`) and `moveObject()` (`ObjectManipulator_ops.cpp:243`) create a new `FWCmdMoveObject` with an **empty** `reference_holders` map, meaning references are not restored. A restored firewall object, for example, comes back without any of its former rule references.

For this reason, we decided not to implement "Deleted Objects" in FirewallFabrik. Deleting an object is permanent (see `object_tree_ops.py:delete_object()`). When importing `.fwb` files, the "Deleted Objects" library is explicitly excluded (`_database.py:_load_xml()`).

Instead, we recommend using Git as a version control system. With the switch from an XML-based backend (Firewall Builder) to YAML (FirewallFabrik), Git makes it easy to restore deleted objects -- including all their references -- by reverting or inspecting previous revisions of the data files.


## Changed Default for "IPv4 Packet Forwarding"

The Linux host settings dialog (`linuxsettingsdialog_q.ui`) includes an "IPv4 Packet forwarding" combo box (`linux24_ip_forward`) with three options:

| UI Label | Stored Value | Effect in Compiled Script |
|---|---|---|
| No change | `''` (empty) | No `echo` statement is generated; the kernel setting is left as-is. FORWARD chain rules are still included (assumes forwarding is already enabled on the target). |
| On | `'1'` | Generates `echo 1 > /proc/sys/net/ipv4/ip_forward`. FORWARD chain rules are included. |
| Off | `'0'` | Generates `echo 0 > /proc/sys/net/ipv4/ip_forward`. FORWARD chain rules are **excluded** from the compiled output, since forwarding is explicitly disabled. |

The same three-state logic applies to IPv6 forwarding (`linux24_ipv6_forward`). The mapping between UI labels and stored values is defined in `linux_settings_dialog.py` (`_COMBO_TEXT_TO_VALUE`), and the script generation happens in `_os_configurator.py` using the `ip_forwarding` configlet.

In Firewall Builder, the default for new firewall objects was "On", which caused the compiled script to always write `1` to `/proc/sys/net/ipv4/ip_forward` -- even for hosts that do not forward traffic. We changed the default to "No change" so that the compiled script does not touch the kernel setting unless the user explicitly opts in.


## The "linux24" Identifier

The identifier `linux24` appears throughout the codebase -- in option names (`linux24_ip_forward`, `linux24_path_iptables`, ...), class names (`OSConfigurator_linux24`), configlet directories (`resources/configlets/linux24/`), and the GUI mapping in `platform_settings.py` (`HOST_OS = {'linux24': 'Linux'}`). Despite the name, it has nothing to do with a specific Linux kernel version.

The name originates from the early 2000s when fwbuilder was developed and Linux 2.4 was the current kernel introducing iptables support. As Linux evolved through 2.6, 3.x, 5.x, and 6.x, the iptables interface and kernel parameter paths (`/proc/sys/net/ipv4/...`) remained the same, so fwbuilder never renamed the identifier. It is defined in fwbuilder's `res/os/linux24.xml` as:

```xml
<Target name="linux24">
  <description>Linux 2.4/2.6</description>
```

In FirewallFabrik, `linux24` is a **host OS identifier** (not a platform). It represents "a Linux system managed via standard kernel parameters and iptables/ip6tables tools". The **platform** identifier is separate -- `iptables` or `nftables` -- and determines which compiler generates the output script. The relationship is: a firewall object has both a platform (what compiler to use) and a host OS (what kernel parameters and tool paths to configure), and `linux24` is the only host OS we support.

Renaming it would break backward compatibility with existing `.fwb` files, configlet templates, and the compiler infrastructure, with no functional benefit. The UI displays it simply as "Linux" (see `platform_settings.py`).


## GUI Architecture

### .ui Files and the Custom UI Loader

PySide6's `QUiLoader` always creates a new top-level widget -- it cannot populate an existing one the way C++ `Ui::setupUi(this)` does. `FWFUiLoader` in `gui/ui_loader.py` works around this by overriding `createWidget()`: when the loader creates the top-level widget (parent is `None`), it returns the existing instance instead of allocating a new one. This lets .ui files fill an already-constructed `QMainWindow` or `QWidget` subclass with all its child widgets, menus, toolbars, and dock widgets.

The .ui files reference roughly 35 custom C++ widget class names (e.g. `FirewallDialog`, `InterfaceDialog`). `CUSTOM_WIDGET_MAP` in the same module maps each name to either a plain Qt base class (as a placeholder) or the real Python implementation once it has been ported. The loader consults this map whenever it encounters an unknown class name.

### Main Window Layout

`FWBMainWindow_q.ui` defines the overall structure:

* **Central widget** -- a `QMdiArea` (`m_space`) that hosts rule set views.
* **Dock widget** (bottom) -- a `QTabWidget` with an *Editor* tab and a *Compiler Output* tab. The Editor tab contains a `QStackedWidget` (`objectEditorStack`) with one page per object editor (Firewall, Host, IPv4, TCP Service, etc.). Clicking an object in the tree switches the stack to the matching editor page.
* **Menu bar, toolbar, and status bar** -- all defined in the same .ui file.

An `ObjectTree` (left-hand side) is added programmatically and placed into a `QSplitter` alongside `m_space`.

### File Naming Conventions

**`*_dialog.py` for both popup dialogs and embedded editor panels.** In fwbuilder, the C++ classes for editor panels are named `*Dialog` (e.g. `FirewallDialog`, `TCPServiceDialog`). The Python files mirror these names so that the fwbuilder source can be cross-referenced easily during porting. This means that files like `device_dialogs.py` (embedded editor panels in `objectEditorStack`) and `preferences_dialog.py` (an actual popup dialog) both use the `_dialog` suffix, even though they serve different purposes. This is intentional.

**Singular vs. plural.** Files containing multiple related editor classes use the plural form (`device_dialogs.py` for `FirewallDialog`, `HostDialog`, `InterfaceDialog`; `service_dialogs.py` for TCP/UDP/ICMP/IP). Files containing a single class use the singular form (`time_dialog.py`, `library_dialog.py`).

**`object_tree_*.py` split.** The object tree implementation is split across five files to keep each one focused:

| File | Responsibility |
|---|---|
| `object_tree.py` | Widget class, signal/slot wiring, event dispatch |
| `object_tree_actions.py` | Context-menu and keyboard-shortcut action handlers |
| `object_tree_data.py` | Constants: icon maps, type lists, folder-to-type mappings |
| `object_tree_menu.py` | Builds context menus and returns handler mappings |
| `object_tree_ops.py` | Database operations (create, delete, duplicate, move) |

**`policy_model.py` / `policy_view.py` for all rule set types.** Despite the name, these files handle Policy, NAT, and Routing rule sets. `PolicyTreeModel` accepts a `rule_set_type` parameter (`'Policy'`, `'NAT'`, or `'Routing'`) and adapts its columns and behavior accordingly. The "policy" prefix was kept because Policy is the primary and most common rule set type.

### Signals and Slots

Connections between signals and slots are established in two ways:

1. **In the .ui file** -- the `<connections>` section wires menu/toolbar actions to slot names (e.g. `fileOpenAction.triggered()` → `fileOpen()`). These are connected automatically when the .ui file is loaded.
2. **In Python** -- explicit `.connect()` calls for signals not covered by the .ui file (e.g. custom tree signals, dynamically created widgets).

A slot must not be connected both ways. If a connection already exists in the .ui file, adding a Python `.connect()` call for the same signal/slot pair will cause the slot to fire twice per signal emission.
