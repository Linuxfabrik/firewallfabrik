# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

tbd


## [v1.4.6] - 2026-04-09

### Added

* User guide: "When to Use the Stateless Option" best practices section covering default deny rules, anti-spoofing rules, loopback rules and DHCP broadcasts

### Changed

* Compile dialog: compiler detail output (ruleset names, etc.) shown in small gray monospace text; each firewall block visually grouped with an underlined heading
* Install dialog: SSH output (banners, MOTD, script output) displayed in small gray monospace text, indented to distinguish it from installer status messages

### Fixed

* All popup dialogs now have a visible border on GNOME/Wayland
* HTML entity `&#x27;` no longer appears instead of apostrophes in the compile log
* Options column in the policy editor now shows the "Options" icon when non-default rule options are set (e.g. stateless, limit, connlimit, hashlimit); also works for NAT and Routing rules
* Rule options icon for `stateless` was missing because `has_nondefault_options()` did not check for it


## [v1.4.5] - 2026-04-09

### Changed

* Compile dialog: "Compile Firewalls" moved from an in-dialog label to the window title bar; firewall sidebar width adapts dynamically to content
* Compile dialog: compiler detail output (ruleset names, etc.) is shown in small gray text; each firewall block is visually grouped with an underlined heading
* Compile dialog: progress column shows "Compiled with Warnings" (orange) or "Compile Error" (red) instead of generic status text

### Fixed

* Compiler warnings (e.g. "Making rule stateless because it matches ICMPv6") no longer cause the compilation to be reported as failed; they are now shown as orange warnings in the GUI and CLI while the exit code remains 0
* Delete key on selected elements in the policy editor was silently ignored due to ambiguous keyboard shortcut registration between Edit menu and Rules menu
* Double-clicking an Options, Action or Comment cell in the policy editor no longer scrolls back to the first rule
* Fix `--require-hashes` pip installs in CI workflows by using pinned versions instead
* Generated iptables shell scripts are now fully POSIX sh compliant and pass shellcheck without warnings: proper variable quoting, `read -r` for backslash safety, `local` replaced with plain variables, backticks replaced with `$()`, `test "X$var"` idiom modernized ([#36](https://github.com/Linuxfabrik/firewallfabrik/issues/36))
* Scrollbars in the object tree and policy editor are now visible (removed custom QSS scrollbar styling that was invisible on some desktop themes)


## [v1.4.4] - 2026-04-08

### Fixed

- Custom Service editor: Platform dropdown always reset to nftables instead of remembering the last selection ([#61](https://github.com/Linuxfabrik/firewallfabrik/issues/61)).
- Sporadic SIGSEGV crash when rebuilding the object tree after compilation or when closing/creating files ([#57](https://github.com/Linuxfabrik/firewallfabrik/issues/57)).


## [v1.4.2] - 2026-04-08

### Fixed

- Images not loading on the MkDocs documentation site due to broken relative paths in HTML image tags.
- Object tree attribute column too narrow on first use when "Show object attributes in the tree" is enabled ([#60](https://github.com/Linuxfabrik/firewallfabrik/issues/60)).


## [v1.4.1] - 2026-04-08

### Added

- Documentation on how to install Release Candidate (RC) versions
- MkDocs-based documentation site, deployed automatically to GitHub Pages

### Changed

- Update pre-commit hooks to latest versions
- Unify CONTRIBUTING with Linuxfabrik standards

### Fixed

- GUI failed to start on Wayland-only systems (e.g. GNOME without X11) because Qt defaulted to the xcb platform plugin ([#58](https://github.com/Linuxfabrik/firewallfabrik/issues/58)).
- Improved Wayland detection to also cover systems where only wayland-egl or wayland-brcm platform plugins are available ([#58](https://github.com/Linuxfabrik/firewallfabrik/issues/58)).
- `pyside6-rcc` not found when installed via `uv tool install` because the tool is inside the isolated virtual environment and not on the user's PATH ([#58](https://github.com/Linuxfabrik/firewallfabrik/issues/58)).
- Pre-compiled Qt resource file (`.rcc`) was written to the wrong directory during package build, causing unnecessary runtime recompilation.
- Sporadic SIGSEGV crash when opening a rule editor (action, comment, direction, metric, options) while another editor had unsaved changes ([#57](https://github.com/Linuxfabrik/firewallfabrik/issues/57)).


## [v1.4.0] - 2026-03-29

### Added

- "Flush entire ruleset" option for both iptables and nftables. When disabled, FirewallFabrik only manages its own tables/chains (e.g. `fwf_filter`, `fwf_nat` for nftables or `fwf_INPUT`, `fwf_FORWARD` for iptables), leaving rules created by other tools like Docker, CrowdSec and fail2ban untouched.

### Changed

- Default output file name changed from firewall object name to `fwf.sh`.
- Default script directory on the firewall changed from `/etc/fw` to `/etc`.
- Default table/chain prefix changed from `linuxfabrik` to `fwf`.

### Fixed

- Application no longer crashes with a segmentation fault when pressing Ctrl+C in the terminal.
- Coexistence mode: `status` command now correctly detects whether the firewall is active, even when other tools like Docker create additional chains.
- Coexistence mode: `stop` command now properly removes all FirewallFabrik chains, including sub-chains with hash-based names (e.g. `fwf_C...`) that were previously left behind ([#42](https://github.com/Linuxfabrik/firewallfabrik/issues/42)).
- Coexistence mode: `stop` command now properly removes FirewallFabrik's chains and jump rules on all systems, including those using the iptables-nft backend.
- Coexistence mode: `stop` command now restores chain policies to ACCEPT so that rules from other tools (Docker, CrowdSec, fail2ban) keep working after stopping the firewall.
- Compiler now generates IPv6 rules (ip6tables / nftables inet) based on the rule set's address family setting ("IPv4 and IPv6") instead of requiring IPv6 addresses on the firewall's interfaces ([#42](https://github.com/Linuxfabrik/firewallfabrik/issues/42)).
- Compiler error and warning messages now show the rule position number instead of the color label.
- IPv6 address and network dialogs now accept prefix lengths 0-128 instead of 1-127 ([#50](https://github.com/Linuxfabrik/firewallfabrik/issues/50)).
- Compiler no longer rejects TCPService objects with a string `'False'` value for the `established` option.
- Extra leading whitespace in generated iptables scripts from inline configlet `{{if}}` blocks removed.
- Generated iptables scripts now abort on `script_body` failure instead of continuing with an incomplete ruleset.
- Generated scripts use `command -v` instead of non-POSIX `which` for checking program availability.
- Harmless Qt/Wayland text-input warnings suppressed during GUI startup.
- Main window border is now clearly visible on GNOME/Wayland.
- `RETVAL` variable is now initialized at script start and set to `1` for invalid arguments.
- `stop_action` in generated iptables scripts now keeps chain policies at DROP instead of setting ACCEPT, preventing the server from being completely open after stop.
- Test infrastructure: expected output files are now also regenerated for firewalls with compiler warnings.


## [v1.3.0] - 2026-03-17

### Added

- Advanced Interface Settings dialog to configure device type (ethernet, VLAN, bridge, bonding), VLAN ID, STP and bonding parameters.
- `Alt+Return` keyboard shortcut opens the editor for the selected object (same as double-click).
- Appearance tab in Preferences — customize fonts for rules, tree and compiler output; toggle direction/action text, comment clipping and toolbar labels.
- Bridge interface configuration support for iptables and nftables using iproute2 (`ip link`).
- Bridge port interfaces are detected automatically from the parent interface type.
- Installer tab in Preferences — configure SSH/SCP paths, timeout and password caching for the built-in policy installer.
- Rules menu: insert, move, copy, cut, paste, remove, disable and enable rules directly from the menu bar.
- Tooltips on all widgets in the platform settings dialogs and the interface editor.
- VLAN sub-interface name validation — warns when the name does not match the parent interface.

### Changed

- About dialog: Linuxfabrik credit visually separated with homepage link (https://www.linuxfabrik.ch).
- Application icon uses PNG at multiple sizes for Wayland compatibility; window icon set via .ui file.
- Default label colors use the Solarized palette throughout; "Purple" renamed to "Cluster", "Gray" renamed to "Maintenance".
- Interface autoconfigure now also runs when opening the editor, not only on save.
- Platform settings dialogs: Script tab shows inline descriptions for each option; Help buttons removed; dialog size reduced.
- Policy rule table borders now match the fwbuilder look (native headers, subtle cell borders).
- Removed XCB/XWayland fallback; fwf runs natively on Wayland.
- Timestamps removed from generated shell scripts to ensure idempotent deployments.
- "Unprotected interface" checkbox removed from the interface editor (not applicable to iptables/nftables).

### Fixed

- Address containment: AddressRange objects were incorrectly treated as "any" address by the shadowing detector.
- Shadowing detection now produces warnings instead of aborting the compilation.


## [v1.2.0] - 2026-03-17

### Added

- Clickable compile log errors scroll to the relevant firewall section (closes #15).
- Cluster Member Management dialog to add/remove firewalls and view interface mappings (closes #26).
- File Properties dialog showing file path, size, and object counts (closes #29).
- Full Firewall Builder compiler parity for iptables and nftables (~130 rule processors ported).
- Import Addresses from File via Tools menu (closes #12).
- Inspect Rules showing all rules referencing the selected object (closes #28).
- Interface name autoconfiguration guesses type and VLAN ID from name patterns.
- Library Export to a separate `.fwf` file (closes #27).
- Library Import from `.fwf` or `.fwb` files.
- NFLOG logging target support for iptables and nftables (closes #18).
- nftables load balancing, address set merging, and separate shadowing pass (closes #22, #23, #24).
- Policy rules now use Preferences defaults for logging, stateful inspection, action, and direction.
- Preferences dialog with Restore Defaults, DNS Name, Address Table, Policy Rules, and Interface tabs.
- Standard service library: Bareos, Keycloak, Kibana, Libvirt, Logstash, OpenSearch.

### Changed

- Generated iptables scripts now run `nft flush ruleset` on systems where `nft` is available.
- Timestamp format in generated scripts changed to ISO 8601.

### Fixed

- "Advanced Interface Settings" button documented as intentionally disabled for iptables/nftables (closes #13).
- False-positive shadowing errors caused by analysis injecting rules into the main pipeline.
- Hardcoded version in generated iptables scripts replaced with the actual package version.
- MAC address edits were silently ignored (fixes #14).
- Multiport rules were broken: TCP flag check incorrectly matched all TCP services (fixes #21).
- Opening objects for editing no longer marks the file as modified when nothing changed (fixes #25).


## [v1.1.0] - 2026-03-16

### Added

- DiffServ (DSCP/TOS) matching for the nftables compiler (`ip dscp` / `ip tos`).
- DSCP symbolic class names (`AF11`, `EF`, `CS3`, etc.) now generate `--dscp-class` in iptables output, matching Firewall Builder behavior.
- Fragment matching (`-f` / `-m frag --fragmore`) and IPv4 option matching (`-m ipv4options`) in the iptables filter compiler (previously only present in the NAT compiler).
- Router-alert IP option (`--ra` / `--flags router-alert`) support in both iptables filter and NAT compilers.
- Tooltips for all IPService dialog fields (protocol number, DSCP, TOS, IP options, fragments).
- Version-aware `ipv4options` module formatting: old module (`--lsrr`, `--ra`) for iptables < 1.4.3, new module (`--flags lsrr,router-alert,...`) for >= 1.4.3.

### Changed

- DiffServ default changed from TOS to DSCP (the modern standard).
- DiffServ radio buttons unselected by default when no code is set; input field disabled until DSCP or TOS is chosen.
- Input widget borders use `palette(dark)` instead of `palette(mid)` for better visibility.

### Fixed

- Boolean flags stored as string `'False'` (truthy in Python) now stored as native booleans.
- DiffServ data keys now consistent across compilers and shadow detection.
- ICMP type/code matching in NAT rules now reads from the correct attribute.
- Rule shadowing false positives for IPService objects (e.g. VRRP) fixed.
- TagService data key inconsistency between dialog and display fixed.
- TCP flags in iptables compiler now read from ORM attributes instead of pre-formatted strings.


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


[Unreleased]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.4.6...HEAD
[v1.4.6]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.4.5...v1.4.6
[v1.4.5]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.4.4...v1.4.5
[v1.4.4]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.4.3...v1.4.4
[v1.4.3]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.4.2...v1.4.3
[v1.4.2]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.4.1...v1.4.2
[v1.4.1]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.4.0...v1.4.1
[v1.4.0]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.3.0...v1.4.0
[v1.3.0]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.2.0...v1.3.0
[v1.2.0]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.1.0...v1.2.0
[v1.1.0]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.0.1...v1.1.0
[v1.0.1]: https://github.com/Linuxfabrik/firewallfabrik/compare/v1.0.0...v1.0.1
[v1.0.0]: https://github.com/Linuxfabrik/firewallfabrik/compare/v0.5.0rc1...v1.0.0
[v0.5.0rc1]: https://github.com/Linuxfabrik/firewallfabrik/compare/v0.5.0b1...v0.5.0rc1
[v0.5.0b1]: https://github.com/Linuxfabrik/firewallfabrik/releases/tag/v0.5.0b1
