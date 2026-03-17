# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

### Added

- GUI: Installer tab in Preferences dialog — configure SSH/SCP paths, timeout and password caching. Settings are used by the firewall installer engine.
- GUI: `Alt+Return` keyboard shortcut opens the editor for the selected object in the tree (same as double-click).
- GUI: Tooltips added to all widgets in iptables, nftables, Linux platform settings dialogs, and the interface editor.
- GUI: Advanced Interface Settings dialog — configure device type (ethernet, VLAN 802.1Q, bridge, bonding), VLAN ID, STP, and bonding parameters.
- GUI: VLAN sub-interface validation — warns when a VLAN-style name (e.g. `eth0.100`) does not match the parent interface name, or when it is created as a top-level interface instead of a sub-interface.
- GUI: Bridge port interfaces are now detected automatically from the parent interface type and display a "Bridge Port Interface" label instead of the regular interface options.
- Compiler: Bridge interface configuration support for iptables and nftables. The `update_bridge` configlet now uses iproute2 (`ip link`) instead of the deprecated `brctl`.

### Changed

- GUI: Platform settings dialogs — Script tab redesigned with inline descriptions for each option. Help buttons removed from all platform settings dialogs.
- GUI: Platform settings dialog size reduced (removed oversized minimum widths, checkbox indicators top-aligned).
- GUI: Removed "Unprotected interface" checkbox from the interface editor (not supported by iptables/nftables).

### Fixed

- Compiler: Shadowing detection now produces warnings instead of aborting the compilation, matching fwbuilder behaviour.


## [v1.2.0] - 2026-03-17

### Added

Compiler — full Firewall Builder parity:

- The iptables and nftables compilers now implement all ~130 rule processors from Firewall Builder. Generated scripts should be functionally identical to Firewall Builder output. Major areas that were completed:
  - Correct handling of REJECT rules with TCP RST and mixed TCP/non-TCP services.
  - Service separation for multiport, TCP flags, source ports, UserService, and CustomService.
  - Address range handling, dynamic interface validation, zero-address detection.
  - Mangle table support (MARK, CLASSIFY, ROUTE, CONNMARK) for iptables.
  - NAT: negation via temporary chains, SDNAT splitting, load balancing, masquerade conversion, virtual addresses, branch rules, and comprehensive validation.
  - Bridge-mode firewall broadcast/multicast forwarding.
  - Accounting chains with user-defined packet/byte counters.
  - Cluster failover interface replacement.
  - Runtime AddressTable and DNSName object handling.
  - Circular group reference detection (aborts compilation).
  - Shadowing detection now runs as a separate compilation pass for more accurate results.
  - Interface group expansion, interface negation, time interval splitting.
  - Loopback interface address expansion, unnumbered interface handling.
- NFLOG logging target support (closes #18). When enabled in firewall settings, the compiler generates `-j NFLOG` (iptables) or `log group N` (nftables) instead of `-j LOG`. Parameters for netlink group, copy range, and queue threshold are supported.
- nftables-specific optimizations:
  - Native load balancing using `numgen inc mod N map { ... }` for DNAT rules with multiple backends, instead of one rule per backend (closes #22).
  - Address set merging: consecutive rules differing only in source or destination address are combined into `ip saddr { addr1, addr2, ... } accept` (closes #23).
  - Separate shadowing detection pass for improved accuracy (closes #24).
  - Validation processors (TCP established flag, zero addresses, unnumbered interfaces, ICMPv6 statelessness, dynamic interfaces, loopback expansion) added to the nftables policy pipeline.
- Standard service library: added Bareos Director/File Daemon/Storage Daemon (9101-9103), Keycloak (8443), Kibana (5601), Libvirt (16509), Logstash Beats Input (5044), Logstash API (9600), OpenSearch (9200), OpenSearch Transport (9300).

GUI:

- Cluster Member Management dialog: add/remove firewalls from a cluster and view interface mappings (closes #26).
- Library Import: import libraries from `.fwf` or `.fwb` files into the current project via File > Import Library. Skips the Standard library and libraries that already exist.
- Library Export: export selected user libraries to a separate `.fwf` file via File > Export Library (closes #27).
- Inspect Rules: show all rules referencing the selected object via Rules > Inspect or the toolbar icon (closes #28).
- File Properties: show file path, size, and object counts via File > Properties (closes #29).
- Import Addresses from File: import IPv4/IPv6 addresses and networks from a text file via Tools > Import Addresses (closes #12).
- Compile log errors matching "Rule N" are now clickable and scroll to the relevant firewall section (closes #15).
- Preferences dialog: enabled DNS Name, Address Table, Policy Rules, and Interface sub-tabs with working settings. Removed obsolete items (deleted objects, advanced user mode, custom templates), unused tabs (Data File, Installer, Diff), and the marginal "Use name for DNS record" option. Fixed truncated text in Policy Rules tab. Replaced all "fwbuilder"/"Firewall Builder" references with "FirewallFabrik" in user-visible UI strings.
- DNS Name and Address Table dialogs now honour the Preferences default for compile-time vs run-time resolution when creating new objects.
- New policy rules now use Preferences defaults for logging, stateful inspection, action, and direction instead of hardcoded values.
- Preferences dialog: "Restore Defaults" button resets all settings (objects, labels, platforms) to application defaults. Policy Rules defaults for source/destination/service/interface ("Any" vs "Dummy" placeholder) now take effect when creating new rules. Description text explains the "Dummy" concept.
- Interface name autoconfiguration: when enabled in Preferences > Interface, the interface type and VLAN ID are guessed from the name (e.g. `eth0.100` → VLAN 802.1q with ID 100, `bond0` → bonding, `br0` → bridge). Supports Linux naming conventions including systemd predictable names (`enp0s3`, `wlp2s0`).

### Fixed

- Multiport rules were broken (fixes #21): rules with multiple TCP ports were split into individual `--dport` rules instead of using `-m multiport --dports`. Root cause: the TCP flag check incorrectly matched all TCP services.
- Opening a firewall, interface, or rule set for editing marked the file as modified even when nothing was changed (fixes #25). Multiple causes: editor wrote back default values for missing keys, read-only toggling fired spurious change signals, and IPv4/IPv6 combo state was compared incorrectly.
- MAC address edits in PhysAddressDialog were silently ignored because a slot stub shadowed the change signal (fixes #14).
- False-positive "Rule X shadows Rule Y" errors caused by shadowing analysis injecting rules into the main pipeline.
- Hardcoded version `0.1.0` in generated iptables scripts replaced with the actual package version.
- "Open Interface" button documented as intentionally disabled for iptables/nftables — no platform-specific interface options exist (closes #13).

### Changed

- Timestamp format in generated scripts changed from `Mon Mar 16 20:06:24 2026` to `2026-03-16 20:06:24 (Mon)` (ISO 8601, all platforms).
- Generated iptables scripts now run `nft flush ruleset` before `reset_iptables_v4/v6` on systems where `nft` is available. On RHEL 8+ and modern distros, `iptables` uses the nftables backend, and pre-existing nftables rules would not be cleared by `iptables -F` alone.


## [v1.1.0] - 2026-03-16

### Added

- DiffServ (DSCP/TOS) matching for the nftables compiler (`ip dscp` / `ip tos`).
- DSCP symbolic class names (`AF11`, `EF`, `CS3`, etc.) now generate `--dscp-class` in iptables output, matching Firewall Builder behavior.
- Fragment matching (`-f` / `-m frag --fragmore`) and IPv4 option matching (`-m ipv4options`) in the iptables filter compiler (previously only present in the NAT compiler).
- Router-alert IP option (`--ra` / `--flags router-alert`) support in both iptables filter and NAT compilers.
- Tooltips for all IPService dialog fields (protocol number, DSCP, TOS, IP options, fragments).
- Version-aware `ipv4options` module formatting: old module (`--lsrr`, `--ra`) for iptables < 1.4.3, new module (`--flags lsrr,router-alert,...`) for >= 1.4.3.

### Fixed

- **Boolean string truthiness**: GUI stored boolean flags (IP options, fragments, etc.) as string `'False'` which is truthy in Python. The GUI now stores native booleans; compilers use a defensive `_is_true()` guard for backward compatibility.
- **DiffServ data key mismatch**: Compilers and shadow detection read `tos_code`/`dscp_code` but data was stored under `tos`/`dscp`. Keys now match across all components.
- **ICMP type/code in NAT compiler**: Was reading from `srv.data` instead of `srv.codes`, causing ICMP NAT rules to ignore type/code matching.
- **Rule shadowing false positives**: IPService objects (e.g. VRRP) were treated as "any" service because `get_protocol_number()` and `is_any()` did not fall back to `named_protocols.protocol_num`. This caused incorrect "Rule X shadows Rule Y" errors during compilation.
- **TagService key mismatch**: Dialog wrote `data['code']` but group display and tooltips read `data['tagcode']`. Now consistent (`tagcode`).
- **TCP flags in iptables compiler**: Was reading pre-formatted strings from `srv.data` instead of ORM attributes `srv.tcp_flags`/`srv.tcp_flags_masks`. Now reads the ORM attributes and formats for iptables like Firewall Builder.

### Changed

- DiffServ default changed from TOS to DSCP (the modern standard).
- DiffServ radio buttons are now unselected by default when no code is set. The code input field is disabled until the user selects DSCP or TOS, making it clear that the choice has no effect without a code value.
- Input widget borders use `palette(dark)` instead of `palette(mid)` for better visibility.


## [v1.0.1] - 2026-03-11

### Fixed

- Platform YAML defaults not included in pip-installed packages (missing `MANIFEST.in` entry).


## [v1.0.0] - 2026-03-08

### Added

- CLI compilers (`fwf-ipt`, `fwf-nft`) accept multiple firewall names and `--all` flag; database is loaded once for all firewalls.
- Collabora Online, Icinga, Nextcloud notify_push and WinRM added to the standard library.
- Compile time intervals and clean up time dialog.
- Confirm-delete dialog when deleting objects that are still in use.
- DNS "Resolve Name" button implemented for IPv4 and IPv6 address dialogs.
- DynamicGroup editor with criteria table and matched-objects preview.
- Example files shipped with the distribution.
- File > Reload action to re-read the current file from disk.
- FreeIPA service group added to the standard library.
- MIME type definitions for `.fwf` and `.fwb` files for file manager integration.
- NAT and Routing rule display support with title bar dirty-state indicator.
- Parallel compilation in the GUI: multiple firewalls compile concurrently using up to N CPU cores, with ordered log output.
- Platform and OS option defaults defined in YAML as single source of truth, replacing scattered hardcoded dicts.
- Settings dialogs now show tooltips and placeholder defaults from the YAML schema.
- Subfolder paste, drag & drop, and nested object creation in the object tree.
- System theme icons (Breeze, Adwaita, etc.) for toolbar and menu actions, with QRC fallback.
- Title labels on MDI rule set panels and Del key support for deleting rules.
- Undo stack entries prefixed with the device name for clarity.
- Window menu and automatic opening of firewall Policy on file load.

### Fixed

- `.fwb` imports allowed to compile and install without requiring a prior save.
- Clipboard router now correctly routes Ctrl+C/X/V to focused text widgets.
- Compiler option lookup (`get_option`) now raises `KeyError` on unknown keys, catching typos at the earliest possible moment; all inline Python fallbacks removed in favour of YAML defaults.
- Context menus and sub-interfaces aligned with fwbuilder behavior.
- Dead menu entries removed (File Compare, SNMP Discovery, Policy Import, Library Import/Export, Print, Help Contents/Index).
- DynamicGroup, AddressTable and DNSName now allowed in rule src/dst cells.
- Find & Replace scope, tree filter, element display, and MDI refresh.
- Focus moves to next element in a rule cell after deleting an object.
- ICMP type/code now read from the codes field instead of data.
- Keywords renamed to Tags in context menus.
- Last-active rule set persisted by name instead of UUID for stability across imports.
- Legacy Firewall Builder compiler paths (`fwb_ipt`, `fwb_nft`) detected during `.fwb` import; a dialog offers to clear them so FirewallFabrik uses its built-in compiler.
- Linux host settings now save under canonical `linux24_conntrack_*` keys matching the compiler.
- Lock/Unlock menu actions wired up to tree selection.
- MDI views refresh on object rename; undo descriptions are now human-readable.
- Model class name used instead of `.type` in `duplicate_object`.
- Netmask shown in tree when editing an address under an interface.
- New objects created via the toolbar menu now land in the selected custom folder.
- Nftables compiler now correctly generates `tcp flags != syn ct state new drop` rules when `accept_new_tcp_with_no_syn` is disabled (was reading a non-existent key).
- Object deletion fixed: str-vs-UUID type mismatch in where-used reference queries.
- Object tree auto-selects the Policy item when opening a file.
- ORM objects flushed before raw `rule_elements` INSERT to avoid integrity errors.
- Output pane context menu shows Ctrl+C and Ctrl+A shortcuts.
- Parent firewall `lastModified` timestamp updated on child/rule/shared-object edits.
- Readonly flag passed to tree items with updated lock icons.
- Rule shadowing detection enabled by default; error messages include rule position numbers.
- Time dialog uses YYYY-MM-DD date format and sensible defaults.
- Title bar double-click on Wayland now works (XCB fallback).

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


[Unreleased]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.2.0...HEAD
[v1.2.0]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.1.0...v1.2.0
[v1.1.0]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.0.1...v1.1.0
[v1.0.1]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.0.0...v1.0.1
[v1.0.0]: https://github.com/Linuxfabrik/firewallfabrik/compare/v0.5.0rc1...v1.0.0
[v0.5.0rc1]: https://github.com/Linuxfabrik/firewallfabrik/compare/v0.5.0b1...v0.5.0rc1
[v0.5.0b1]: https://github.com/Linuxfabrik/firewallfabrik/releases/tag/v0.5.0b1
