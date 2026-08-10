# Screenshot Replacement Checklist

Tracking issue: [#17](https://github.com/Linuxfabrik/firewallfabrik/issues/17)

Every PNG under `docs/user-guide/img/` is a Firewall Builder capture. None has been replaced yet. On top of that, three chapters reference images that were never captured at all, and a number of files on disk are no longer referenced by any chapter. This file is the inventory.

Rebuild the numbers below with the commands under "Verifying the inventory" before trusting them.

## Inventory

| Metric                                              | Count |
|-----------------------------------------------------|-------|
| Unique images referenced by the chapters             | 450   |
| Files present in `img/`                              | 436   |
| Referenced and present (need a re-shoot)             | 367   |
| Referenced but **missing** (broken links)            | 83    |
| Present but **orphaned** (referenced by nothing)     | 69    |

Roughly 20 of the 367 present files are product-neutral artwork: network topology diagrams and packet-header tables, almost all in the cookbook. Those need no re-shoot, at most a style pass. The real capture workload is about 347 re-shoots plus 83 new captures.

## Per chapter

| Chapter                              | Refs | Present | Missing | Notes                                                        |
|--------------------------------------|------|---------|---------|--------------------------------------------------------------|
| 01 - Introduction                    | 1    | 1       | 0       | file is still named `firewall-builder-main-window.png`        |
| 02, 03, 06, 11, 12, 16, 17           | 0    | -       | -       | no images                                                     |
| 04 - FirewallFabrik GUI              | 26   | 26      | 0       | `vdc.fwf`                                                     |
| 05 - Working with Objects            | 121  | 121     | 0       | 12 blocked or not capturable, see below                       |
| **07 - Firewall Policies**           | 50   | **0**   | **50**  | 27 `policy-*`, 23 `nat-*`                                     |
| **08 - Cluster Configuration**       | 8    | **0**   | **8**   | blocked on cluster support                                    |
| **09 - Configuration of Interfaces** | 25   | **0**   | **25**  | `vdc.fwf` plus a VLAN/bridge/bonding fixture                  |
| 10 - Compiling and Installing        | 32   | 32      | 0       | 3 cluster shots blocked                                       |
| 13 - Configlets                      | 1    | 1       | 0       | `vdc.fwf`                                                     |
| 14 - Cookbook                        | 184  | 184     | 0       | 96 cluster, 16 packet tagging, 6 branch, 66 doable            |
| 15 - Troubleshooting                 | 2    | 2       | 0       | `vdc.fwf`                                                     |

## Broken links (83) - highest priority

Chapters 07, 08 and 09 ship without a single rendering image. These files were never committed, so this is not a deletion to revert: they have to be captured from scratch. `mkdocs.yml` sets `validation.links.not_found: 'info'`, so the build does not fail and the breakage is easy to miss.

Chapter 07 has a second, independent defect: the prose cites "Figure 7.1, 7.2, 7.3, 7.5, 7.7, 7.12, 7.24, 7.25, 7.26", but no alt text in that chapter carries a `Figure N.N` label, so the numbers point at nothing even once the images exist. `Figure 7.12` is cited five times and carries a full rule #0/#1/#2 walkthrough. Fix the numbering in the same pass as the captures.

### 07 - Firewall Policies (50, in document order)

- [ ] policy-access-policies, policy-destination-rfc1918, policy-traffic-directions, policy-modifying-direction
- [ ] policy-reject-action-responses, policy-rule-actions, policy-iptables-options-dialog
- [ ] policy-multiple-rule-sets, policy-rule-set-dialog-iptables, policy-passing-packet-to-mgmt
- [ ] nat-rule-set, nat-translation-rules, nat-source-translation-directions, nat-firewall-object-details
- [ ] nat-basic-snat-rule, nat-dynamic-interface-config, nat-port-translation-rule, nat-tcp-service-sport-range
- [ ] nat-address-range-object, nat-load-balancing-rule, nat-network-object-small, nat-network-object-in-rule
- [ ] nat-http-translation-rule, nat-dnat-firewall-interface, nat-dnat-directions, nat-firewall-ip-for-server
- [ ] nat-dnat-using-interface, nat-dnat-using-address, nat-policy-rule-with-nat
- [ ] nat-dynamic-external-interface, nat-dnat-dynamic-rule, nat-tcp-service-port-8080, nat-port-translation-dnat
- [ ] policy-routing-rule, policy-ecmp-routing-rule, policy-modifying-rules, policy-modifying-objects
- [ ] policy-changing-action, policy-changing-direction, policy-rule-options-menu, policy-basic-rule-no-options
- [ ] policy-classify-string-editor, policy-rule-with-classify, policy-rules-without-grouping
- [ ] policy-creating-group, policy-naming-group, policy-group-one-entry, policy-adding-to-group
- [ ] policy-group-of-rules, policy-collapsed-group

`nat-source-translation-directions` and `nat-dnat-directions` are diagrams, not screenshots. Their alt texts carry the whole explanation (variants A/B/C), so they have to be drawn rather than captured.

### 08 - Cluster Configuration (8)

- [ ] cluster-failover-group-mapping, cluster-failover-group-config
- [ ] cluster-heartbeat-parameters, cluster-openais-parameters
- [ ] cluster-state-sync-group-tree, cluster-state-sync-group-parameters
- [ ] cluster-conntrack-parameters, cluster-rule-set-override-warning

### 09 - Configuration of Interfaces (25)

- [ ] iface-example-ipv4-ipv6-config, iface-config-after-address-removal
- [ ] iface-error-incorrect-vlan-name, iface-advanced-settings-vlan, iface-disable-name-checking
- [ ] iface-vlan-config-linux, iface-adding-vlan-subinterface, iface-vlan-subinterface-eth1-100
- [ ] iface-vlan-parameters-dialog, iface-two-vlans-with-addresses
- [ ] iface-vlan-renamed-eth1-102, iface-vlans-renamed-naming-scheme
- [ ] iface-bridge-enable-settings, iface-bridge-config-linux, iface-bridge-interface-br0
- [ ] iface-bridge-type-settings, iface-bridge-ports-configured, iface-bridge-port-disabled-functions
- [ ] iface-bridge-add-third-port, iface-bridge-vlan-subinterface, iface-bridge-ports-child-objects
- [ ] iface-bridge-vlan-as-bridge-ports
- [ ] iface-bonding-settings, iface-bonding-two-slaves, iface-bonding-enable-settings

## Re-shoots by chapter

### 01 - Introduction (1)

- [ ] `firewall-builder-main-window.png` - rename to `firewallfabrik-main-window.png` and update the reference in the chapter

### 04 - FirewallFabrik GUI (26)

Capture against `vdc.fwf` with the `firewall` firewall expanded in the tree.

- [ ] gui-main-window, gui-menu-and-tool-bars, gui-object-tree, gui-policy-area
- [ ] gui-object-editor, gui-find-and-replace, gui-output-view, gui-undo-stack-panel
- [ ] gui-toolbar-buttons, gui-object-tree-structure, gui-standard-objects
- [ ] gui-object-tree-without-subfolders, gui-add-firewalls-subfolder, gui-moving-objects-to-subfolder
- [ ] gui-subfolders-for-firewalls, gui-empty-filter-field, gui-populated-filter-field
- [ ] gui-object-attributes-column, gui-create-objects-button
- [ ] gui-creating-objects-using-object-menu, gui-creating-objects-by-right-clicking
- [ ] gui-policy-and-undo-stack, gui-added-inside-range-and-outside-range
- [ ] gui-removed-outside-range-from-source, gui-added-outside-range-2-to-destination
- [ ] gui-preferences-dialog

The Preferences dialog has five tabs in FirewallFabrik (Objects, Installer, Labels, Appearance, Platforms and OS). fwbuilder had seven. "Platforms and OS" lists exactly two platforms and one OS.

### 05 - Working with Objects (121)

Most object-editor shots can use existing objects in `vdc.fwf`. For the New Firewall walkthrough start from an empty database.

- [ ] obj-firewall-wizard-first-page (fresh DB)
- [ ] obj-firewall-controls, obj-host-os-settings-dialog, obj-firewall-settings-dialog
- [ ] obj-rule-set-options, obj-interface-object-* and the remaining interface shots
- [ ] obj-physical-address-object, obj-host-with-mac-matching, obj-rule-address-and-physical
- [ ] obj-host-* (host objects with multiple addresses and interfaces)
- [ ] obj-network-object, obj-ipv6-*, obj-address-range-object, obj-object-group
- [ ] obj-tcp-service-*, obj-udp-service-*, obj-icmp-*, obj-ip-service-*, obj-custom-service-*
- [ ] obj-time-interval-*, obj-user-service-*, obj-dns-name-*, obj-address-table-*
- [ ] obj-dynamic-group-*, obj-keywords-*, obj-library-*, obj-multicast-*, obj-broadcast-*
- [ ] obj-ipset-*, obj-bridge-interface-*, obj-find-replace-* (referenced subset), obj-policy-*
- [ ] obj-new-cluster-menu, obj-cluster-right-click-menu, obj-cluster-wizard-members, obj-cluster-wizard-populated **(cluster fixture)**
- [ ] obj-attached-network-child-object, obj-attached-network-context-menu, obj-attached-network-editing, obj-attached-network-nat-rule **(blocked by #85)**
- `obj-attached-network-diagram` is artwork, no capture needed

List the current set with `grep -oE 'img/obj-[^)"]+' "05 - Working with Objects.md" | sort -u`.

### 10 - Compiling and Installing a Policy (32)

Standalone shots work with any of the five firewalls in `vdc.fwf`.

- [ ] compile-main-toolbar-icons, compile-policy-toolbar-icons, compile-context-menu-options
- [ ] compile-single-rule, compile-generated-iptables-gui, compile-policy-example, compile-select-firewalls
- [ ] compile-uncompiled-firewalls-bold, compile-object-editor-timestamps
- [ ] compile-status-messages-error, compile-successful
- [ ] compile-cluster-two-members, compile-all-cluster-firewall-objects, compile-member-as-standalone-warning **(cluster fixture)**
- [ ] install-rules-install-menu, install-select-compile-and-install, install-ssh-parameters, install-status-success
- [ ] install-management-interface-checkbox, install-advanced-settings-address, install-options-alternative-address
- [ ] install-advanced-settings-username, install-advanced-settings-ssh-access, install-advanced-settings-alternate-port
- [ ] install-ssh-identity-parameters, install-select-compile-install-wizard, install-options-dialog
- [ ] install-new-rsa-key-dialog, install-successful-session, install-batch-select-firewalls
- [ ] install-batch-options, install-batch-progress

The installer uses OpenSSH `ssh`/`scp` directly, so the SSH parameter shots differ from fwbuilder's.

### 13 - Configlets (1)

- [ ] configlet-firewall-settings-dialog (any firewall in `vdc.fwf`, Settings tab)

### 14 - FirewallFabrik Cookbook (184)

66 images are doable with `vdc.fwf` or a small edit on top of it:

- [ ] Changing IP Addresses in Firewall Configuration Created from a Template (10)
- [ ] Firewall Object used in Examples (1)
- [ ] Permit Internal LAN to Connect to the Internet (1)
- [ ] Allowing Specific Protocols Through, while Blocking Everything Else (1)
- [ ] Letting Certain Protocols through from a Specific Source (1)
- [ ] Anti-spoofing rules (1), Anti-Spoofing Rules for a Firewall with a Dynamic Address (1)
- [ ] Using Groups (2), Using an Address Range Instead of a Group (2)
- [ ] Controlling Access to the Firewall (7)
- [ ] Controlling Access to Different Ports on the Server (3)
- [ ] Firewall Talking to Itself (1)
- [ ] Blocking Unwanted Types of Packets (3)
- [ ] Using Action 'Reject': Blocking Ident Protocol (2)
- [ ] Using Negation in Policy Rules (3)
- [ ] Running Multiple Services on the Same Machine on Different Virtual Addresses and Different Ports (3)
- [ ] Using a Firewall as the DHCP and DNS Server for the Local Net (3)
- [ ] Controlling Outgoing Connections from the Firewall (3)
- [ ] A Different Method for Preventing SSH Scanning Attacks: iptables "recent" (2)
- [ ] Using an Address Table Object to Block Access from Large Lists of IP Addresses (2)
- [ ] "1-1" NAT (1), "No NAT" Rules (2), Redirection Rules (1)
- [ ] Destination NAT Onto the Same Network (2), "Double" NAT (4)
- [ ] Basic Rate Limiting (4)

118 images need a fixture that does not exist yet:

- [ ] Tagging Packets (16) - packet tagging fixture
- [ ] Branching Rules (4) and the external-script SSH-scan recipe (2) - branch fixture, blocked by #90
- [ ] Web Server Cluster Running Linux (26) - cluster fixture, blocked by #84
- [ ] Linux Cluster Using VRRPd (18) - cluster fixture
- [ ] Linux Cluster Using Heartbeat (24) - cluster fixture
- [ ] Linux Cluster Using Heartbeat and VLAN Interfaces (15) - cluster and VLAN fixture
- [ ] Using Clusters to Manage Firewall Policies on Multiple Servers (14) - cluster fixture
- [ ] Creating Local Firewall Rules for a Cluster Member (10) - cluster fixture

The cluster recipes contain most of the product-neutral topology diagrams. Sort artwork out from screenshots before estimating a cluster batch.

### 15 - Troubleshooting (2)

- [ ] troubleshoot-dns-on-loopback, troubleshoot-dns-to-name-servers (any firewall, dummy rule)

## Orphaned files (69)

Present in `img/`, referenced by no chapter. Do not delete them in bulk: some are leftovers of deliberately removed sections, others may mark prose that got lost during the import. Decide per file while re-shooting the owning chapter.

12 of them belong to platform sections that were removed for good and are safe to delete on sight:

- Cisco: install-cisco-router-options, install-cisco-session-finish, install-cisco-session-log, obj-ip-service-cisco-rule
- PF / OpenBSD: obj-ip-service-pf-rule, os-new-firewall-wizard-pf, os-rcconf-disabled-openbsd, os-firewall-settings-rcconf-mode, os-generated-rcconf-format, os-firewall-settings-file-names
- PuTTY / plink: install-plink-host-key-prompt, troubleshoot-putty-configuration

The remaining 57 need a decision:

- `cookbook-*` (26): 056, 057, 071, 078, 089-095, 121-126, 166-170, 194, 201, 204, 207
- `gui-*` (15): clusters-fwb, copy-and-pasting-between-windows, data-file, data-file-menu, dmz-server, locked-object, object-in-top-window, preferences-appearance-tab, preferences-data-file-tab, preferences-installer-tab, preferences-labels-tab, preferences-objects-tab, preferences-platforms-and-os-tab, unlocked-object, window-menu
- `obj-*` (13): address-table-bad-hosts, address-table-bad-hosts-rules, find-object-dialog-details, find-replace-buttons, find-replace-complete, find-replace-final, find-replace-results, find-replace-scope, network-zones-diagram, policy-after-replace, udp-service-dialog, udp-service-source-port-range, udp-source-port-rule
- `install-preferences-installer-tab` (1)
- `troubleshoot-any-to-any-firewall`, `troubleshoot-any-to-any-firewall-loopback` (2)

The six orphaned `gui-preferences-*-tab` files are worth a second look: FirewallFabrik has a Preferences dialog with five tabs, so those shots could be re-shot and re-linked instead of dropped.

## Not capturable

The feature does not exist in FirewallFabrik, so these need a text change rather than a new screenshot.

- `obj-snmp-community-string`, `obj-snmp-discovered-interfaces`, `obj-snmp-discovery-output`: there is no SNMP discovery. `gui/ui/FWBMainWindow_q.ui` still carries a `DiscoveryDruidAction`, but it is disabled and wired into no menu. Chapter 06 already states the feature is absent.
- `obj-preconfigured-firewall-templates`, `obj-editing-template-interfaces`: the New Host and New Firewall dialogs have no template pages (`gui/new_host_dialog.py`).

Anything showing Cisco, PF, ipfw, ipfilter, HP ProCurve or PuTTY has no counterpart either. FirewallFabrik supports iptables and nftables on Linux only (`gui/platform_settings.py`). All such files are already orphaned.

## Blockers

| Issue                                                             | Blocks                                                          |
|-------------------------------------------------------------------|-----------------------------------------------------------------|
| [#84](https://github.com/Linuxfabrik/firewallfabrik/issues/84) Cluster support incomplete, [#78](https://github.com/Linuxfabrik/firewallfabrik/issues/78) Failover Group | chapter 08 (8), 3 shots in chapter 10, 4 in chapter 05, 96 in the cookbook |
| [#85](https://github.com/Linuxfabrik/firewallfabrik/issues/85) AttachedNetworksDialog missing | 4 `obj-attached-network-*` shots in chapter 05                    |
| [#90](https://github.com/Linuxfabrik/firewallfabrik/issues/90) Branch action incomplete | 6 cookbook images                                                 |

## Fixture coverage

| Fixture       | Covers                                                                     |
|---------------|-----------------------------------------------------------------------------|
| `vdc.fwf`     | GUI, objects, policies, NAT, routing, compile, install, troubleshooting      |
| (none yet)    | Cluster Configuration, cluster cookbook recipes                              |
| (none yet)    | VLAN, bridge and bonding interfaces (chapter 09)                             |
| (none yet)    | Branching rules and the SSH-scan branch recipes                              |
| (none yet)    | Packet tagging recipes                                                       |

`examples/vdc.fwf` contains five firewalls (`cloud`, `firewall`, `infra`, `monitor`, `proxy`) plus a populated object library. When you build a missing fixture, add it under `examples/` and list it here so later re-shoots use the same source.

## Working tips

- Pick a chapter, walk it top to bottom, capture in document order. Match the existing dimensions roughly so the page layout does not shift.
- Keep the existing filenames so the markdown stays untouched. The one exception is `firewall-builder-main-window.png` in chapter 01.
- Use a clean theme (Adwaita default) and a consistent window size across a chapter.
- Do not commit placeholder images. A broken link is easier to find than a placeholder.
- After a batch, drop a comment on #17 listing what is done, and update the counts in this file.

## Verifying the inventory

```bash
cd docs/user-guide
grep -ohE '\(img/[A-Za-z0-9._-]+\.png\)|src="img/[A-Za-z0-9._-]+\.png"' *.md \
  | grep -oE 'img/[A-Za-z0-9._-]+\.png' | sed 's|img/||' | sort -u > /tmp/ref.txt
ls img > /tmp/pres.txt
wc -l < /tmp/ref.txt                          # referenced
wc -l < /tmp/pres.txt                         # present
comm -23 /tmp/ref.txt /tmp/pres.txt           # broken links
comm -13 /tmp/ref.txt /tmp/pres.txt           # orphans
```
