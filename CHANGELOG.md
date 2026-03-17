# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

tbd


## [v1.2.0] - 2026-03-17

### Added

- **iptables REJECT rule correctness** (Phase 1): `SplitRuleIfSrvAnyActionReject` splits Reject rules with srv=any into TCP RST + ICMP unreachable. `SplitServicesIfRejectWithTCPReset` separates mixed TCP/non-TCP services when TCP RST is configured. `CheckForTCPEstablished` aborts compilation if the deprecated "established" TCP flag is used. Pipeline reordered to match fwbuilder's processor sequence.
- **Service separation framework** (Phase 2): New `compiler/processors/_service.py` with `SeparateServiceObject` base class and concrete separators (`SeparateTCPWithFlags`, `SeparateSrcPort`, `SeparateSrcAndDstPort`, `SeparateUserServices`, `SeparateCustom`, `SeparateTagged`). `VerifyCustomServices` aborts if a CustomService has no code for the target platform. Inserted into the iptables pipeline after `GroupServicesByProtocol`.
- **Stub processor implementations** (Phase 3): `CheckInterfaceAgainstAddressFamily` drops rules where the interface has no matching addresses. `SpecialCaseWithUnnumberedInterface` removes unnumbered/bridge-port interfaces from src/dst. `CheckForStatefulICMP6Rules` forces ICMPv6 rules to stateless mode. `Optimize2` clears service on final rules (except Reject+TCP RST). `CheckForObjectsWithErrors` checks for objects flagged with errors.
- **Address range & dynamic interface handling** (Phase 4): `SpecialCaseAddressRangeInSrc/Dst` replaces single-address ranges with proper address objects. `SplitIfSrcMatchingAddressRange/Dst` splits rules when an address range matches the firewall. `CheckForDynamicInterfacesOfOtherObjects` aborts if dynamic interfaces of other hosts/firewalls are used. `CheckForUnnumbered` catches unnumbered interfaces used as addresses. `CheckForZeroAddr` catches 0.0.0.0 addresses and /0 netmask typos.
- **Logging, FW special cases, validation** (Phase 5): `Logging1` applies the global `log_all` option. `SpecialCaseWithFW1` splits fw-to-fw rules into Inbound + Outbound. `SpecialCaseWithFWInDstAndOutbound` drops impossible outbound rules with fw in dst. `ExpandLoopbackInterfaceAddress` replaces loopback interface refs with actual addresses. `ExpandMultipleAddressesIfNotFWInSrc/Dst` expands addresses while preserving firewall identity. `OptimizeForMinusIOPlus` removes redundant wildcard interface in INPUT/OUTPUT. `CheckMACInOUTPUTChain` and `CheckUserServiceInWrongChains` validate chain compatibility.
- **Mangle table support** (Phase 6): Complete MARK/CLASSIFY/ROUTE support with 16 processors including `SplitIfTagClassifyOrRoute`, `SplitIfTagAndConnmark`, `RouteProcessor`, chain assignment for tagging/classification/routing, CONNMARK handling, and mangle-specific validation.
- **NAT compiler parity** (Phase 7): 21 new NAT processors including `DoOSrcNegation/DoODstNegation/DoOSrvNegation` (temp chain negation), `SplitSDNATRule`, `ConvertLoadBalancingRules`, `SplitNATBranchRule`, `DynamicInterfaceInODst/TSrc`, `AddVirtualAddress`, `AlwaysUseMasquerade`, `SplitMultiSrcAndDst`, `SplitMultipleICMP`, `ConvertToAtomicForOSrv/ItfInb/ItfOutb`, `VerifyRules2/3`, and `SeparateSrcPort/SrcAndDstPort` for NAT.
- **Bridging & accounting** (Phases 8-9): `BridgingFw` handles bridge-mode firewall broadcast/multicast forwarding. `Accounting` creates user-defined chains for packet/byte counting with RETURN targets.
- **Recursive group detection**: `RecursiveGroupsInRE` aborts compilation on circular group references. Added to all pipelines (iptables policy/NAT, nftables policy/NAT).
- **Shadowing detection enhancements** (Phase 10): `ConvertAnyToNotFWForShadowing`, `SplitIfSrcAnyForShadowing`, `SplitIfDstAnyForShadowing` improve shadowing accuracy when "firewall is part of any" is off.
- **Cluster failover interface replacement**: `ReplaceClusterInterfaceInItfRE` replaces cluster interfaces with member firewall interfaces (shared processor).
- **Runtime MultiAddress processing**: `ProcessMultiAddressObjectsInSrc/Dst` handles runtime AddressTable/DNSName objects by splitting them into separate rules and registering with the OS configurator.
- **nftables validation processors**: Added `CheckForTCPEstablished`, `CheckForObjectsWithErrors`, `CheckForStatefulICMP6Rules`, `CheckForZeroAddr`, `CheckForUnnumbered`, `ExpandLoopbackInterfaceAddress`, `CheckForDynamicInterfacesOfOtherObjects` to the nftables policy pipeline.
- **Standard service library**: Added Bareos Director/File Daemon/Storage Daemon (9101-9103), Keycloak (8443), Kibana (5601), Libvirt (16509), Logstash Beats Input (5044), Logstash API (9600), OpenSearch (9200), OpenSearch Transport (9300).
- **nftables native load balancing** (closes #22): DNAT rules with multiple TDst addresses use `numgen inc mod N map { 0 : addr1, 1 : addr2, ... }` instead of creating N separate rules. Round-robin load balancing with optional port forwarding.
- **nftables address set merging** (closes #23): Consecutive rules with identical chain/action/interface that differ only in source or destination address are merged into nftables sets: `ip saddr { addr1, addr2, addr3 } accept`. Reduces output size for firewalls with many similar rules.
- **Separate shadowing detection pass** (closes #24): Shadowing analysis now runs as a separate compilation pass before the main pipeline, matching fwbuilder's architecture. The separate pass uses `ConvertAnyToNotFWForShadowing`, `SplitIfSrcAnyForShadowing`, `SplitIfDstAnyForShadowing`, and `ConvertToAtomic` for precise analysis without injecting extra rules into the main pipeline.
- **Cluster Member Management dialog** (closes #26): New dialog for managing cluster members — add/remove firewalls from a cluster and view interface mappings. Includes `ClusterMemberDialog` and updated `ClusterGroupDialog` with .ui files.
- **Library Export dialog** (closes #27): New File > Export Library action to export selected user libraries to a separate `.fwf` file. Shows a dialog with checkboxes to select which libraries to include.
- **Inspect Rules dialog** (closes #28): New dialog (Tools > Inspect or right-click > Inspect) shows all policy/NAT/routing rules that reference the selected object, listing firewall, rule set, rule position, and action.
- **File Properties dialog** (closes #29): New dialog (File > Properties) shows file metadata: path, size, and object counts (firewalls, hosts, networks, services, rules, libraries).
- **Import Addresses from File** (closes #12): New Tools menu action to import addresses from a text file. Supports IPv4/IPv6 hosts, CIDR networks, netmask notation, and comments. Creates Address/Network objects in the selected library.
- **NFLOG logging target** (closes #18): The compiler now honours the `use_NFLOG` firewall option. iptables generates `-j NFLOG --nflog-group N --nflog-prefix "..." [--nflog-range N] [--nflog-threshold N]` instead of `-j LOG`. nftables generates `log group N prefix "..."`. NFLOG parameters (`ulog_nlgroup`, `ulog_cprange`, `ulog_qthreshold`) are enabled in platform defaults. Automatic rules (drop_invalid_and_log) also support NFLOG. Existing LOG functionality is unchanged when NFLOG is not enabled.
- **Full fwbuilder parity**: Interface group expansion (`ExpandGroupsInItf`, `ExpandGroupsInSrv`), cluster interface replacement (`ReplaceClusterInterfaceInItfRE`), interface negation (`SingleObjectNegationItf`, `ItfNegation`, `ItfInbNegation`, `ItfOutbNegation`), time negation (`TimeNegation`), interval splitting (`ConvertToAtomicForIntervals`), `SpecialCasesWithCustomServices` (ESTABLISHED/RELATED in CustomService code), and `InterfacePolicyRulesWithOptimization` (chain-optimized interface splitting). NAT additions: `ExpandGroupsInItfInb/Outb`, `NATSpecialCaseWithUnnumberedInterface`, `NATCheckForDynamicInterfacesOfOtherObjects`, `VerifyRuleWithMAC`, `NATExpandAddressRanges`, `NATProcessMultiAddressObjectsInRE` (4 slots), `CheckForObjectsWithErrors`. nftables additions: `SpecialCaseWithFW1`, `TimeNegation`, `ConvertToAtomicForIntervals`, `ExpandGroupsInItf`.

### Fixed

- **Multiport rules broken** (fixes #21): `SeparateTCPWithFlags` incorrectly separated ALL TCP services because the standard library stores `tcp_flags: {urg: false, ...}` — a non-empty dict. Now checks `tcp_flags_masks` for actual flag inspection (matching fwbuilder's `inspectFlags()`). Also hardened `_print_dst_service_from_rule` to only emit `--dports` when `ipt_multiport` flag is set, preventing `--dports` without `-m multiport`.
- **Hardcoded version** in iptables top comment: replaced `'0.1.0'` with `firewallfabrik.__version__`.
- **`Firewall` object has no attribute `is_any`**: `SplitIfSrcMatchingAddressRange`, `SplitIfDstMatchingAddressRange`, and `SpecialCaseWithFW1` called `is_any()` on src/dst objects that could be `Firewall` instances. `Firewall` inherits from `Host`, not `Address`.
- **False-positive shadowing errors**: Shadowing enhancement processors (`ConvertAnyToNotFWForShadowing`, `SplitIfSrcAnyForShadowing`, `SplitIfDstAnyForShadowing`) injected extra rules into the main pipeline causing "Rule X shadows Rule Y" false positives. Removed from inline pipeline (require a separate compilation pass like in fwbuilder).
- **Opening objects marks file as modified without user changes** (fixes #25): Three root causes fixed. (1) `apply_all()` unconditionally wrote `comment` and `keywords` back — now compares before writing. (2) `_apply_changes()` in device/ruleset dialogs injected new default keys (e.g. `management: false`, `mangle_only_rule_set: false`) into data dicts that didn't have them — new `_set_data_key()` helper only writes keys that already exist or have non-default values. (3) `_set_read_only()` ran after `_loading = False`, causing `setEnabled()` to fire widget signals that triggered spurious `apply_all()` calls — now runs inside the loading guard. (4) `RuleSetDialog` wrote `ipv4: true` to rule sets where `ipv4` was `False` (SQLAlchemy default) but the combo showed IPv4 — now compares combo index against the index that `_populate()` would compute.
- **PhysAddressDialog changes silently ignored** (fixes #14): The `@Slot() def changed()` stub shadowed the `BaseObjectDialog.changed` Signal, so edits to MAC address fields never triggered `apply_all()`. Now delegates to `_on_changed()`.
- **"Open Interface" button stub** (closes #13): Documented as intentionally disabled for iptables/nftables — no platform-specific interface options exist for these platforms.
- **Compile log error navigation** (closes #15): Error lines matching "Rule N" are now rendered as clickable links. Clicking scrolls to the firewall's compile output section.

### Changed

- **Timestamp format** in generated scripts: `Mon Mar 16 20:06:24 2026` → `2026-03-16 20:06:24 (Mon)` (all platforms).
- **`nft flush ruleset` in iptables scripts**: On RHEL8+ and modern distros, `iptables` uses the nftables backend (`iptables-nft`). The generated `reset_all()` function now runs `nft flush ruleset` (if `nft` is available) before `reset_iptables_v4/v6` to clear any pre-existing nftables rules that `iptables -F` would not remove.


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
