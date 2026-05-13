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
Compile each firewall and compare the generated `.fw` script to the output from Firewall Builder (iptables only, since Firewall Builder never had an nftables compiler). The FirewallFabrik iptables compiler is at full feature parity with Firewall Builder, so the scripts should be functionally equivalent. Minor formatting differences (e.g. whitespace) are expected but do not affect functionality. Note that FirewallFabrik no longer embeds a generation timestamp in the script header (see [Key Differences from Firewall Builder](#key-differences-from-firewall-builder)).

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

These platforms are not supported:

| Platform | Target | Status |
|----|----|----|
| Cisco FWSM | Firewall Services Module | End-of-sale 2012, end-of-support 2015 ([Cisco EoL notice](https://www.cisco.com/c/en/us/products/collateral/interfaces-modules/services-modules/end_of_life_notice_c51-458222.html)). |
| Cisco PIX | PIX 6.x appliances | End-of-sale 2008, end-of-support 2013. Replaced by Cisco ASA ([Wikipedia](https://en.wikipedia.org/wiki/Cisco_PIX)). |
| ipfilter (ipf) | Solaris, FreeBSD | Still present in FreeBSD base and illumos. Removed from Oracle Solaris in 11.4 ([Wikipedia](https://en.wikipedia.org/wiki/IPFilter)). |
| ipfw | FreeBSD, macOS | Still maintained in FreeBSD base alongside PF and ipfilter. macOS deprecated ipfw in 10.7 Lion (2011) and removed it in 10.10 Yosemite (2014), replaced by PF ([Wikipedia](https://en.wikipedia.org/wiki/Ipfirewall)). |

### Platforms Not Yet Supported

These platforms are still in use but no compiler backend has been implemented yet. Firewall objects for these platforms are imported but cannot be compiled.

| Platform | Target | Notes |
|----|----|----|
| Cisco ASA | ASA 7.x--8.3 | The Firewall Builder compiler targeted ASA up to version 8.3. ASA 9.x would require a substantially new compiler. Cisco is migrating customers to Firepower Threat Defense (FTD) ([Wikipedia](https://en.wikipedia.org/wiki/Cisco_ASA)). |
| Cisco IOS ACL | IOS 12.1--12.4 routers | Current routers run IOS-XE 17.x LTS, with year-based 26.x releases starting in 2026 ([Cisco IOS XE 26 release bulletin](https://www.cisco.com/c/en/us/products/collateral/ios-nx-os-software/ios-xe-26/bulletin-c25-2378701.html)). Architecturally possible to add. |
| Cisco NX-OS ACL | Nexus 4.2--6.1 | Current NX-OS train is 10.x ([Cisco Nexus 9000 release notes](https://www.cisco.com/c/en/us/support/switches/nexus-9000-series-switches/products-release-notes-list.html)). Architecturally possible to add. |
| HP ProCurve ACL | ProCurve K.13 switches | ProCurve brand retired in 2010 (renamed HP Networking), consolidated under HPE Aruba after the 2015 Aruba acquisition ([Wikipedia](https://en.wikipedia.org/wiki/ProCurve)). |
| Juniper JunOS | JunOS 11.2+ | Current Junos OS is in the 25.x series ([Wikipedia](https://en.wikipedia.org/wiki/Junos_OS)). |
| PF | OpenBSD, FreeBSD | Used by pfSense and OPNsense ([Wikipedia](https://en.wikipedia.org/wiki/PfSense)). Among the unsupported platforms, the most natural candidate for a future backend. |

### Added in FirewallFabrik

| Platform | Target | Notes |
|----|----|----|
| nftables | Linux (kernel 3.13+) | The successor to iptables and the default firewall framework on all major Linux distributions. Firewall Builder never supported nftables ([Linux 3.13 release notes](https://kernelnewbies.org/Linux_3.13)). |

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
The ULOG logging target was removed from the Linux kernel in 3.17, replaced by NFLOG ([Linux 3.17 release notes](https://kernelnewbies.org/Linux_3.17)). The `use_ULOG` firewall option is no longer part of the FirewallFabrik schema; if your `.fwb` file had it enabled, it is silently migrated to the standard LOG target during import. Both compilers fully support NFLOG: the iptables compiler generates `-j NFLOG` rules with `--nflog-group`, `--nflog-prefix`, `--nflog-range`, and `--nflog-threshold` parameters; the nftables compiler generates `log group N` statements. Enable NFLOG via the "Use NFLOG" option in the firewall settings dialog.

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
