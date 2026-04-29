# Screenshot Replacement Checklist

Tracking issue: [#17](https://github.com/Linuxfabrik/firewallfabrik/issues/17)

All 436 PNGs under `docs/user-guide/img/` were captured from fwbuilder and need
to be retaken from FirewallFabrik. The recommended fixture is `examples/vdc.fwf`,
which contains 5 firewalls (`cloud`, `firewall`, `infra`, `monitor`, `proxy`)
plus a populated object library. Cluster, branch and packet-tagging chapters
need additional fixtures — see "Fixture coverage" below.

Replace one chapter at a time. After replacing a batch, drop a comment in #17
listing what is done so the issue trail stays useful.

## Fixture coverage

| Fixture     | Covers                                                                |
|-------------|------------------------------------------------------------------------|
| `vdc.fwf`   | GUI, objects, policies, NAT, routing, interfaces, compile, troubleshoot |
| (none yet)  | Cluster Configuration (chap 8) + cluster cookbook recipes              |
| (none yet)  | Branching Rules + SSH-scan branch recipes                              |
| (none yet)  | Packet Tagging recipes                                                 |

When you create the missing fixtures, add them under `examples/` and reference
them here so future re-shoots pick the same source.

## Chapters

### 01 - Introduction (1 image, vdc-doable)

- [ ] `firewall-builder-main-window.png` - rename to `firewallfabrik-main-window.png` and update reference

### 04 - FirewallFabrik GUI (26 images, vdc-doable)

Capture against the loaded `vdc.fwf` with the `firewall` firewall expanded in the tree.

- [ ] gui-main-window
- [ ] gui-menu-and-tool-bars
- [ ] gui-object-tree
- [ ] gui-policy-area
- [ ] gui-object-editor (partial view)
- [ ] gui-find-and-replace (partial view)
- [ ] gui-output-view (partial view)
- [ ] gui-undo-stack-panel
- [ ] gui-toolbar-buttons
- [ ] gui-object-tree-structure
- [ ] gui-standard-objects (Standard library expanded)
- [ ] gui-object-tree-without-subfolders
- [ ] gui-add-firewalls-subfolder
- [ ] gui-moving-objects-to-subfolder
- [ ] gui-subfolders-for-firewalls
- [ ] gui-empty-filter-field
- [ ] gui-populated-filter-field
- [ ] gui-object-attributes-column
- [ ] gui-create-objects-button
- [ ] gui-creating-objects-using-object-menu
- [ ] gui-creating-objects-by-right-clicking
- [ ] gui-policy-and-undo-stack
- [ ] gui-added-inside-range-and-outside-range
- [ ] gui-removed-outside-range-from-source
- [ ] gui-added-outside-range-2-to-destination
- [ ] gui-preferences-dialog (Edit > Preferences)

### 05 - Working with Objects (124 images, mostly vdc-doable)

Almost all object-editor screenshots can use existing objects in `vdc.fwf`.
For the firewall-creation wizard shots, start with a fresh empty database and
walk through "New Firewall".

- [ ] `obj-firewall-wizard-*` (4 images, fresh DB needed)
- [ ] `obj-preconfigured-firewall-templates.png` + `obj-editing-template-interfaces.png`
- [ ] `obj-snmp-*` (3 images, requires SNMP-reachable host)
- [ ] `obj-firewall-controls.png`, `obj-host-os-settings-dialog.png`, `obj-firewall-settings-dialog.png`
- [ ] `obj-new-cluster-*` / `obj-cluster-wizard-*` (4 images, **needs cluster fixture**)
- [ ] `obj-rule-set-options.png`, `obj-interface-object-*` (rest of chapter, vdc-doable)
- [ ] `obj-attached-network-*` (4 images, **needs AttachedNetworks support — currently blocked by #85**)
- [ ] `obj-physical-address-object.png`, `obj-host-with-mac-matching.png`, `obj-rule-address-and-physical.png` (vdc-doable)
- [ ] `obj-host-*` (host objects with multiple addresses, vdc-doable)
- [ ] `obj-network-object.png` and the rest (vdc-doable)

Tip: list missing files with `grep -oE 'img/obj-[^)]+' "05 - Working with Objects.md" | sort -u`.

### 07 - Firewall Policies (50 images, vdc-doable)

The `firewall` firewall in `vdc.fwf` already has policy, NAT and routing rule
sets populated. Use those for most shots; create temporary rules for the
rare cases that need a specific configuration (rate limiting, classify, etc.).

- [ ] All `policy-*` images (access policies, directions, actions, options, rule sets, rule manipulation, grouping)
- [ ] All `nat-*` images (SNAT, DNAT, port translation, address ranges, dynamic interfaces)

### 08 - Cluster Configuration (8 images, **needs cluster fixture**)

Blocked: vdc.fwf has no clusters and Cluster support is incomplete (see #84).
Defer this chapter until cluster work lands, or create a minimal cluster
fixture once #84 / #85 / #78 are resolved.

- [ ] cluster-failover-group-mapping
- [ ] cluster-failover-group-config
- [ ] cluster-heartbeat-parameters
- [ ] cluster-openais-parameters
- [ ] cluster-state-sync-group-tree
- [ ] cluster-state-sync-group-parameters
- [ ] cluster-conntrack-parameters
- [ ] cluster-rule-set-override-warning

### 09 - Configuration of Interfaces (25 images, mostly vdc-doable)

- [ ] iface-example-ipv4-ipv6-config, iface-config-after-address-removal
- [ ] iface-error-incorrect-vlan-name, iface-advanced-settings-vlan, iface-disable-name-checking
- [ ] iface-vlan-* (config, subinterface adding, parameters, two VLANs, renaming)
- [ ] iface-bridge-* (enable, config, type, ports, port disabled functions, add port, vlan-as-bridge-port)
- [ ] iface-bonding-* (settings, two slaves, enable settings)

### 10 - Compiling and Installing a Policy (32 images)

Standalone-firewall shots: vdc-doable using any of the 5 firewalls.
Cluster shots: needs cluster fixture (3 images marked below).

- [ ] compile-main-toolbar-icons, compile-policy-toolbar-icons, compile-context-menu-options
- [ ] compile-single-rule, compile-generated-iptables-gui
- [ ] compile-policy-example, compile-select-firewalls
- [ ] compile-uncompiled-firewalls-bold, compile-object-editor-timestamps
- [ ] compile-status-messages-error, compile-successful
- [ ] compile-cluster-two-members **(needs cluster fixture)**
- [ ] compile-all-cluster-firewall-objects **(needs cluster fixture)**
- [ ] compile-member-as-standalone-warning **(needs cluster fixture)**
- [ ] install-rules-install-menu, install-select-compile-and-install
- [ ] install-ssh-parameters, install-status-success
- [ ] install-management-interface-checkbox, install-advanced-settings-address, install-options-alternative-address
- [ ] install-advanced-settings-username, install-advanced-settings-ssh-access, install-advanced-settings-alternate-port
- [ ] install-ssh-identity-parameters
- [ ] install-select-compile-install-wizard, install-options-dialog
- [ ] install-new-rsa-key-dialog, install-successful-session, install-batch-select-firewalls

### 13 - Configlets (1 image, vdc-doable)

- [ ] configlet-firewall-settings-dialog (any firewall in vdc.fwf, Settings tab)

### 14 - FirewallFabrik Cookbook (192 images)

Recipes that fit `vdc.fwf` directly or with minor edits:

- [ ] Permit Internal LAN to Connect to the Internet (1)
- [ ] Allowing Specific Protocols Through, while Blocking Everything Else (varies)
- [ ] Letting Certain Protocols through from a Specific Source (1)
- [ ] Anti-spoofing rules
- [ ] Anti-Spoofing Rules for a Firewall with a Dynamic Address
- [ ] Using Groups (2)
- [ ] Using an Address Range Instead of a Group (2)
- [ ] Controlling Access to the Firewall (7)
- [ ] Controlling Access to Different Ports on the Server (3)
- [ ] Firewall Talking to Itself (1)
- [ ] Blocking Unwanted Types of Packets (3)
- [ ] Using Action 'Reject': Blocking Ident Protocol (2)
- [ ] Using Negation in Policy Rules (3)
- [ ] Running Multiple Services on the Same Machine on Different Virtual Addresses and Different Ports (3)
- [ ] Using a Firewall as the DHCP and DNS Server for the Local Net (3)
- [ ] Controlling Outgoing Connections from the Firewall (3)
- [ ] "1-1" NAT, "No NAT" Rules (2), Redirection Rules (1)
- [ ] Destination NAT Onto the Same Network (2), "Double" NAT (4)
- [ ] Basic Rate Limiting (4)

Recipes that **need a separate fixture**:

- [ ] Tagging Packets (16) — packet-tagging fixture
- [ ] Branching Rules (4) — branch fixture, blocked by #90
- [ ] Using Branch Rule Set with External Script ... SSH Scanning Attacks (2) — branch + script fixture
- [ ] A Different Method for Preventing SSH Scanning Attacks ... iptables "recent" (2)
- [ ] Using an Address Table Object to Block Access from Large Lists of IP Addresses (2)
- [ ] Web Server Cluster Running Linux (25) — cluster fixture, blocked by #84
- [ ] Linux Cluster Using VRRPd (18) — cluster fixture
- [ ] Linux Cluster Using Heartbeat (22) — cluster fixture
- [ ] Linux Cluster Using Heartbeat and VLAN Interfaces (15) — cluster + VLAN fixture
- [ ] Using Clusters to Manage Firewall Policies on Multiple Servers (14) — cluster fixture
- [ ] Creating Local Firewall Rules for a Cluster Member (10) — cluster fixture

### 15 - Troubleshooting (2 images, vdc-doable)

- [ ] troubleshoot-dns-on-loopback (any firewall, dummy rule)
- [ ] troubleshoot-dns-to-name-servers

## Working tips

- Pick a chapter, walk top-to-bottom in the .md, capture each shot in order. Match the existing dimensions roughly so the layout doesn't shift.
- Use a clean theme (Adwaita default) and consistent window size for visual consistency across chapters.
- Drop a `🐧` placeholder image only as last resort - prefer leaving the broken link until the screenshot is ready.
- The .md files reference images by relative path `img/<name>.png`. Keep the existing filenames so you do not need to touch the markdown.
