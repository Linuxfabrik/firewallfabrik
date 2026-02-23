# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

### Added

- Compile time intervals and clean up time dialog.
- Confirm-delete dialog when deleting objects that are still in use.
- DynamicGroup editor with criteria table and matched-objects preview.
- Example files shipped with the distribution.
- File > Reload action to re-read the current file from disk.
- FreeIPA service group added to the standard library.
- Collabora Online, Icinga, Nextcloud notify_push and WinRM added to the standard library.
- NAT and Routing rule display support with title bar dirty-state indicator.
- Platform default options (log_level, log_prefix) applied automatically for new firewalls.
- Subfolder paste, drag & drop, and nested object creation in the object tree.
- System theme icons (Breeze, Adwaita, etc.) for toolbar and menu actions, with QRC fallback.
- Title labels on MDI rule set panels and Del key support for deleting rules.
- Undo stack entries prefixed with the device name for clarity.
- Window menu and automatic opening of firewall Policy on file load.

### Fixed

- Clipboard router now correctly routes Ctrl+C/X/V to focused text widgets.
- Context menus and sub-interfaces aligned with fwbuilder behavior.
- DynamicGroup, AddressTable and DNSName now allowed in rule src/dst cells.
- Find & Replace scope, tree filter, element display, and MDI refresh.
- Focus moves to next element in a rule cell after deleting an object.
- ICMP type/code now read from the codes field instead of data.
- Keywords renamed to Tags in context menus.
- Last-active rule set persisted by name instead of UUID for stability across imports.
- Lock/Unlock menu actions wired up to tree selection.
- MDI views refresh on object rename; undo descriptions are now human-readable.
- Model class name used instead of `.type` in `duplicate_object`.
- Netmask shown in tree when editing an address under an interface.
- Object tree auto-selects the Policy item when opening a file.
- ORM objects flushed before raw `rule_elements` INSERT to avoid integrity errors.
- Output pane context menu shows Ctrl+C and Ctrl+A shortcuts.
- Parent firewall `lastModified` timestamp updated on child/rule/shared-object edits.
- Readonly flag passed to tree items with updated lock icons.
- Rule shadowing detection enabled by default; error messages include rule position numbers.
- Time dialog uses YYYY-MM-DD date format and sensible defaults.
- `.fwb` imports allowed to compile and install without requiring a prior save.

### Changed

- Decouple GUI components with ClipboardStore, PolicyViewBridge, and focus registration.
- Extract ClipboardRouter, EditorManager, and RuleSetWindowManager from FWWindow.
- Extract TreeActionHandler from ObjectTree.
- Extract context-menu builders from PolicyView into a dedicated module.
- Modernize UI with comprehensive QSS stylesheet.
- Object tree rewritten into 4 focused modules.
- Replace tree clipboard global with instance attribute and add paste validation.


## [v0.5.0rc1] - 2026-02-13

### Added

- CIDR notation parsing in IPv4/IPv6 editor dialogs and editor breadcrumb.
- Center compile dialog on screen and persist its geometry.
- Firewalls needing recompilation shown in bold in the object tree.
- Highlight only the clicked cell in rule view and protect default Any elements.
- Input validation and widget constraints for all editor dialogs.
- RuleSet editor dialog for Policy, NAT and Routing.
- Show asterisk in title bar when file has unsaved changes.

### Fixed

- Address range end field auto-filled when start field loses focus.
- Bool-coerced inactive flag from XML loader handled correctly.
- Compiler/installer remote paths and file names corrected.
- Context menu actions deferred to prevent SIGSEGV on tree clear.
- Compile, Install and Save actions disabled when no file is loaded.
- Default Qt icon replaced with the FirewallFabrik app icon.
- Deprecated Qt5 margin property removed from .ui files.
- Host OS Settings options disabled for unsupported nftables features.
- Platform Settings options disabled for unsupported compiler features.
- Qt5 signal/slot mismatch in the find panel .ui file corrected.
- Skip Any sentinel objects in rule element display.
- Warn before overwriting existing .fwf when saving an imported .fwb.

### Changed

- Erroneous QSS styling removed.
- Include .qss files in build output.


## [v0.5.0b1] - 2026-02-13

Initial public beta pre-release.

### Added

- Compile and install workflow for iptables and nftables platforms.
- Ctrl+Shift+N shortcut for File > New Object File.
- Ctrl+Shift+S shortcut for File > Save As.
- Detailed object tooltips ported from fwbuilder to the rule editor.
- File > Close (Ctrl+F4) to close the current document.
- Group dialog with drag & drop support.
- Host wizard dialog ported from fwbuilder.
- Library folder structure with nested group placement.
- MDI rule set windows with multi-select drag, clipboard, delete and context menu.
- Modernized Qt6 appearance with Fusion style and central stylesheet.
- nftables settings dialog.
- Object tree with Delete context menus and New [Type] for group-based folders.
- Panels hidden when no database file is loaded.
- Resource compilation from .qrc at build time.
- Restore last active object and MDI rule set when reopening a file.
- Rule number column display and platform combo defaults.
- Service library expanded with Wikipedia multi-service ports.
- Single-rule compile for the correct platform, with error for unsupported platforms.

### Fixed

- Accept new TCP with no SYN option corrected.
- Firewall modified timestamp updated when changing host/platform settings.
- Flush pending editor changes before save/close/switch.
- IPv4/IPv6 order option corrected.
- Object tree strikethrough and MDI titles refreshed on inactive toggle.
- Stub slots added for unimplemented .ui connections; unused UI elements disabled.

### Changed

- Fixture database caching with sqlite3 serialize/deserialize for faster tests.


[Unreleased]: https://github.com/Linuxfabrik/firewallfabrik/compare/v0.5.0rc1...HEAD
[v0.5.0rc1]: https://github.com/Linuxfabrik/firewallfabrik/compare/v0.5.0b1...v0.5.0rc1
[v0.5.0b1]: https://github.com/Linuxfabrik/firewallfabrik/releases/tag/v0.5.0b1
