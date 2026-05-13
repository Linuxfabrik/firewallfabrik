# Migrating from Firewall Builder

## Overview

FirewallFabrik is a modernized port of [Firewall Builder](http://sourceforge.net/projects/fwbuilder) (fwbuilder). If you already have Firewall Builder `.fwb` files, you can import them directly into FirewallFabrik and continue working with your existing firewall configurations.

This chapter explains the import process, what to expect, and where FirewallFabrik differs from Firewall Builder.

## Importing a .fwb File

1.  Open FirewallFabrik and select **File \> Open** (or press `Ctrl+O`).
2.  In the file dialog, select **Firewall Builder files (\*.fwb)** from the file type filter and choose your `.fwb` file.
3.  FirewallFabrik parses the XML, converts all objects and rule sets, and loads them into the editor.
4.  You can now work with your firewalls, objects, and policies exactly as before.

> [!NOTE]
> When you save, the file is always written in the FirewallFabrik YAML format (`.fwf`). The original `.fwb` file is not modified.
>
> If a `.fwf` file with the same base name already exists, FirewallFabrik will warn you before overwriting it.

## Post-Import Checklist

After importing a `.fwb` file, verify the following:

**Compiler paths**  
Firewall Builder stored paths to its own compilers (`fwb_ipt`, `fwb_nft`) in each firewall object. FirewallFabrik detects these legacy paths and offers to clear them so that the built-in compiler is used instead. Accept this dialog unless you have a specific reason not to.

**Platform settings**  
Review each firewall's platform and host OS settings (right-click the firewall \> Edit). FirewallFabrik provides sensible defaults for all options via its YAML-based defaults system, but you should verify that the imported values match your environment.

**Compile and compare**  
Compile each firewall and compare the generated `.fw` script to the output from Firewall Builder. The iptables and nftables compilers are at full feature parity with Firewall Builder — the scripts should be functionally equivalent. Minor formatting differences (e.g. whitespace) are expected but do not affect functionality. Note that FirewallFabrik no longer embeds a generation timestamp in the script header (see [Key Differences from Firewall Builder](#key-differences-from-firewall-builder)).

**Save as .fwf**  
Once you are satisfied, save the file (`Ctrl+S`). This creates the `.fwf` file that you will use going forward.

## What Gets Imported

FirewallFabrik imports all objects, rule sets, and settings from a `.fwb` file:

- Firewalls, hosts, interfaces, and addresses
- Policy, NAT, and routing rule sets with all rule elements
- Object groups, service groups, and dynamic groups
- Address tables, DNS names, and address ranges
- Time intervals and custom services
- Clusters and cluster groups
- Libraries and their folder structure
- Object comments and tags
- Platform and host OS settings

## What Does Not Get Imported

- **Revision history (RCS)** -- Firewall Builder had optional RCS integration. FirewallFabrik does not support RCS; use Git for version control instead.
- **Deleted Objects library** -- Firewall Builder soft-deleted objects into a special library. FirewallFabrik uses permanent deletion. See the [developer guide](../developer-guide/DesignDecisions.md) for the rationale.
- **Unsupported platform settings** -- If your `.fwb` file contains firewalls configured for platforms that FirewallFabrik does not support (e.g. Cisco PIX, PF), the objects are imported but cannot be compiled. See [Platform Compatibility](#platform-compatibility) below.

## Platform Compatibility

Firewall Builder supported compilation to nine firewall platforms. FirewallFabrik ships with an **iptables** backend at full feature parity with Firewall Builder, plus a new **nftables** backend that Firewall Builder never had.

### Discontinued Platforms

These platforms have no remaining audience and are not supported:

| Platform | Target | Status |
|----|----|----|
| Cisco FWSM | Firewall Services Module | End-of-sale 2012, end-of-support 2015.[^cisco-fwsm] Effectively gone from production networks. |
| Cisco PIX | PIX 6.x appliances | End-of-sale 2008, end-of-support 2013.[^cisco-pix] Replaced by Cisco ASA. |
| ipfilter (ipf) | Solaris, FreeBSD | Oracle Solaris has minimal market share. Still present in FreeBSD base and illumos, but largely supplanted by PF in new deployments.[^ipfilter] |
| ipfw | FreeBSD, macOS | Still maintained in FreeBSD base alongside PF and ipfilter, but mostly displaced by PF in practice. macOS deprecated ipfw in 10.7 Lion (2011) and removed it in 10.10 Yosemite (2014), in favor of PF.[^ipfw] |

### Platforms Not Yet Supported

These platforms are still in use but no compiler backend has been implemented yet. Firewall objects for these platforms are imported but cannot be compiled.

| Platform | Target | Notes |
|----|----|----|
| Cisco ASA | ASA 7.x--8.3 | Still widely deployed. The Firewall Builder compiler targeted ASA up to version 8.3. Modern ASA 9.x would require a substantially new compiler. Cisco is transitioning to Firepower Threat Defense (FTD).[^cisco-asa] |
| Cisco IOS ACL | IOS 12.1--12.4 routers | Cisco IOS routers remain common (modern versions run IOS-XE 17.x LTS, with Cisco moving to year-based 26.x releases from 2026 onward).[^cisco-ios-xe] Architecturally possible to add. |
| Cisco NX-OS ACL | Nexus 4.2--6.1 | Cisco Nexus switches are used in data centers (current NX-OS is 10.x).[^cisco-nx-os] Architecturally possible to add. |
| HP ProCurve ACL | ProCurve K.13 switches | ProCurve brand retired in 2010 (renamed HP Networking), later consolidated under HPE Aruba after the 2015 Aruba acquisition.[^procurve] A niche switch ACL platform. |
| Juniper JunOS | JunOS 11.2+ | Juniper is a major player in enterprise networking (current Junos OS is in the 25.x series).[^junos] |
| PF | OpenBSD, FreeBSD | Actively developed, powers pfSense and OPNsense.[^pfsense] Among the unsupported platforms, PF would be the most natural candidate for a future backend. |

### Added in FirewallFabrik

| Platform | Target | Notes |
|----|----|----|
| nftables | Linux (kernel 3.13+) | The successor to iptables and the default firewall framework on all major Linux distributions. Firewall Builder never supported nftables.[^nftables] |

## Key Differences from Firewall Builder

File format  
FirewallFabrik uses YAML (`.fwf`) instead of XML (`.fwb`). The YAML format is human-readable, diff-friendly, and works well with Git.

No RCS  
Version control is handled externally (Git recommended) instead of built-in RCS.

No deleted objects library  
Objects are permanently deleted. Use Git to recover accidentally deleted objects.

No SNMP discovery  
The SNMP-based network discovery feature has been removed. Create objects manually or import from a `.fwb` file.

No policy import  
Firewall Builder could parse the output of `iptables-save` and create firewall objects and rule sets from it. This feature required a complex ANTLR parser (~47,000 lines of code) and produced a flat, unsorted rule list that needed extensive manual cleanup to be usable. In practice, building a firewall from scratch in the GUI is faster than cleaning up an imported configuration. FirewallFabrik does not include this feature.

ULOG removed, NFLOG supported  
The ULOG logging target has been removed from modern Linux kernels (replaced by NFLOG).[^ulog] The `use_ULOG` firewall option is no longer part of the FirewallFabrik schema; if your `.fwb` file had it enabled, it is silently migrated to the standard LOG target during import. Both compilers fully support NFLOG: the iptables compiler generates `-j NFLOG` rules with `--nflog-group`, `--nflog-prefix`, `--nflog-range`, and `--nflog-threshold` parameters; the nftables compiler generates `log group N` statements. Enable NFLOG via the "Use NFLOG" option in the firewall settings dialog.

Numeric syslog levels  
The `use_numeric_log_levels` firewall option is honoured by the iptables compiler: when enabled, LOG rules are emitted with `--log-level 5` instead of `--log-level notice`, matching the form every iptables version understands out of the box. The option is not available for nftables, whose native syntax requires the symbolic name.

Legacy logging and bridge options  
Several advanced iptables options (log TCP sequence numbers, log TCP/IP options, kernel timezone for time-based rules, unconditional rule logging, bridge interface configuration, management SSH rule in block/stop action) are legacy features with no remaining audience and are not yet implemented in the fwf compiler. The corresponding checkboxes in the iptables firewall settings dialog are present but disabled. In the nftables firewall settings dialog these iptables-only options have been removed entirely, since nftables either provides native alternatives (for example, IPv6 neighbor discovery via native `icmpv6` matches, or `nftables` sets in place of the ipset kernel module) or does not support them at all. If your `.fwb` file had any of these options enabled, you will see a compiler warning.

Desktop integration  
FirewallFabrik registers `.fwf` and `.fwb` MIME types for file manager integration. See [02 - Installing FirewallFabrik](02%20-%20Installing%20FirewallFabrik.md) for setup instructions.

Compiler parity  
The iptables compiler implements all ~130 rule processors from Firewall Builder, including negation via temporary chains, mangle table support (MARK/CLASSIFY/ROUTE/CONNMARK), address range handling, bridging firewall mode, accounting chains, load balancing (NAT), multiport optimization, and comprehensive validation. The nftables compiler provides equivalent functionality using native nftables features (sets instead of multiport, inline negation, etc.). Generated scripts should be functionally identical to Firewall Builder output.

nftables support  
FirewallFabrik adds native nftables compilation, which Firewall Builder never had.

Parallel compilation  
FirewallFabrik compiles multiple firewalls concurrently (up to the number of CPU cores). Firewall Builder compiled firewalls one at a time. The CLI compilers (`fwf-ipt`, `fwf-nft`) also accept multiple firewall names and an `--all` flag, loading the database only once.

DiffServ default  
Firewall Builder defaulted to "Use TOS" in the IPService dialog when neither TOS nor DSCP was set. FirewallFabrik defaults to neither selected — the DSCP/TOS code field is disabled until the user explicitly chooses DSCP or TOS, making it clear that the setting has no effect without a code value. When a selection is needed, DSCP is recommended as the modern standard.

IPv4 packet forwarding default  
Firewall Builder defaulted to enabling IPv4 packet forwarding. FirewallFabrik defaults to "No change" (does not modify the kernel setting).

nftables-aware reset  
On RHEL 8+ and modern distributions, `iptables` uses the nftables backend (`iptables-nft`). FirewallFabrik's generated scripts run `nft flush ruleset` before the iptables reset to clear any pre-existing nftables rules that `iptables -F` alone would not remove. This is conditional — on systems where `nft` is not installed, the command is skipped.

No generation timestamp  
Firewall Builder embedded a generation timestamp in every compiled script, which meant that recompiling an unchanged policy always produced a different output file. This broke deterministic builds: checksums changed on every run, `diff` always showed at least one modified line, and CI/CD pipelines could not reliably detect whether the policy had actually changed. FirewallFabrik deliberately omits the generation timestamp so that the same `.fwf` input always produces byte-identical output. If you need to record when a script was deployed, handle this in your deployment process (e.g. Ansible, CI/CD pipeline, or a wrapper script that writes a timestamp to `/etc/fw/deployed-at` on the target host).

## Sources

[^cisco-asa]: Cisco ASA platform history and transition to Firepower Threat Defense: [Cisco ASA on Wikipedia](https://en.wikipedia.org/wiki/Cisco_ASA).
[^cisco-fwsm]: Cisco Firewall Services Module End-of-Life announcement: [Cisco EoL Notice for FWSM](https://www.cisco.com/c/en/us/products/collateral/interfaces-modules/services-modules/end_of_life_notice_c51-458222.html).
[^cisco-ios-xe]: Cisco IOS XE 26 release lifecycle and the move to year-based versioning: [Cisco IOS XE 26 Software Release Bulletin](https://www.cisco.com/c/en/us/products/collateral/ios-nx-os-software/ios-xe-26/bulletin-c25-2378701.html).
[^cisco-nx-os]: Current Cisco Nexus 9000 NX-OS release trains (10.x): [Cisco Nexus 9000 Series Release Notes](https://www.cisco.com/c/en/us/support/switches/nexus-9000-series-switches/products-release-notes-list.html).
[^cisco-pix]: Cisco PIX end-of-sale (2008-07-28) and end-of-support (2013-07-29) dates: [Cisco PIX on Wikipedia](https://en.wikipedia.org/wiki/Cisco_PIX).
[^ipfilter]: IPFilter availability in FreeBSD, illumos, and former Solaris releases: [IPFilter on Wikipedia](https://en.wikipedia.org/wiki/IPFilter).
[^ipfw]: ipfw maintenance status in FreeBSD and removal from macOS in 10.10 Yosemite: [ipfirewall on Wikipedia](https://en.wikipedia.org/wiki/Ipfirewall).
[^junos]: Junos OS 25.x release timeline: [Junos OS on Wikipedia](https://en.wikipedia.org/wiki/Junos_OS).
[^nftables]: nftables introduction in Linux kernel 3.13 (2014-01-19): [Linux 3.13 release notes (kernelnewbies)](https://kernelnewbies.org/Linux_3.13) and [nftables on Wikipedia](https://en.wikipedia.org/wiki/Nftables).
[^pfsense]: pfSense and OPNsense use the PF firewall on FreeBSD: [pfSense on Wikipedia](https://en.wikipedia.org/wiki/PfSense).
[^procurve]: ProCurve renaming to HP Networking (2010) and consolidation under HPE Aruba (2015): [ProCurve on Wikipedia](https://en.wikipedia.org/wiki/ProCurve).
[^ulog]: ULOG netfilter target removal in Linux kernel 3.17: [Linux 3.17 release notes (kernelnewbies)](https://kernelnewbies.org/Linux_3.17).
