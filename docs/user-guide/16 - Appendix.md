# Appendix

This chapter provides additional information that may be useful to FirewallFabrik users.

## iptables ipset Module

FirewallFabrik uses ipset for run-time address tables. The `ipset` package must be installed on the firewall machine if you use Address Table objects in run-time mode.

On most modern Linux distributions, ipset is available as a standard package:

``` bash
# Debian/Ubuntu
apt install ipset

# Fedora/RHEL
dnf install ipset
```

To verify that ipset is working:

``` bash
ipset --version
ipset -N test hash:ip
ipset --list
ipset -X test
```

If `ipset --version` reports an error about missing kernel modules, ensure the `ip_set` kernel module is loaded:

``` bash
modprobe ip_set
```

## nftables Sets

When using nftables as the firewall platform, FirewallFabrik uses native nftables sets instead of ipset. No additional packages are needed beyond the standard `nftables` package:

``` bash
# Debian/Ubuntu
apt install nftables

# Fedora/RHEL
dnf install nftables
```

## Editing the .fwf File Directly

The `.fwf` file is plain YAML. While the GUI is the recommended way to make changes, editing the file directly with a text editor or a tool like `yq` is useful for bulk operations and automation, for example enabling IPv4 forwarding on every firewall at once or changing the log level across a fleet. This section shows how the file is structured and which GUI setting maps to which YAML key.

> [!WARNING]
> The GUI loads the file into an internal database on open and writes it back on save, so saving an open session overwrites any changes you made to the file on disk in the meantime. Either close FirewallFabrik before editing the file by hand, or, if it is still open, run **File > Reload** (`Ctrl+R`) afterwards to discard the in-memory session and load your edited file from disk. Reloading also validates the file, since it is parsed on load. Alternatively, compile the policy before deploying.

### Structure of a .fwf File

A `.fwf` file is a tree of objects. The top level holds `libraries`, each library holds `children`, and groups nest further `children` inside themselves. A firewall therefore typically lives several levels deep, for example under `libraries > User > children > Firewalls group > Firewall`.

Because the nesting depth depends on where an object sits in the tree, do not rely on a fixed positional path when scripting edits. Anchor on the object instead. Every `Firewall` object carries an `options:` map that holds all of its Host OS and platform settings:

``` yaml
libraries:
  - name: 'User'
    children:
      - type: 'ObjectGroup'
        name: 'Firewalls'
        children:
          - type: 'Firewall'
            name: 'cloud'
            data:
              host_OS: 'linux24'
              platform: 'nftables'
            options:
              linux24_ip_forward: '1'      # Host OS: IPv4 Packet forwarding = On
              drop_invalid: true           # Platform: drop INVALID packets
              log_level: 'info'
            interfaces:
              - name: 'eth0'
                # ...
            rule_sets:
              # ...
```

With [`yq`](https://github.com/mikefarah/yq) you can, for example, turn on IPv4 forwarding for every firewall in the file. Match on `type == "Firewall"` so the change applies only to firewall objects and not to rules, which carry their own `options:` block:

``` bash
yq --inplace '(.. | select(tag == "!!map" and .type == "Firewall").options.linux24_ip_forward) = "1"' myconfig.fwf
```

> [!NOTE]
> Keys that are left at their default value are usually omitted from the file. When a key is missing, the default from the tables below applies. Setting a key explicitly always wins over the default.

### GUI to YAML Mapping

The following tables list every setting from the firewall settings dialogs and the matching key under the firewall's `options:` map. Host OS settings use the same name in the GUI and the YAML file; platform settings use a different internal key, so always look the key up here rather than guessing from the GUI label.

<!-- BEGIN GENERATED firewall-options-mapping -->

### Host OS settings (Firewall > Host OS Settings ...)

| Tab | GUI field | YAML key (under `options:`) | Type / values | Default | Platform |
|---|---|---|---|---|---|
| Options | Accept ICMP redirects | `linux24_accept_redirects` | tri-state (`''` no change, `'1'` on, `'0'` off) | `''` | iptables, nftables |
| Options | Accept source route | `linux24_accept_source_route` | tri-state (`''` no change, `'1'` on, `'0'` off) | `''` | iptables, nftables |
| conntrack | HASHSIZE | `linux24_conntrack_hashsize` | integer (`-1` = kernel default) | `-1` | iptables, nftables |
| conntrack | CONNTRACK_MAX | `linux24_conntrack_max` | integer (`-1` = kernel default) | `-1` | iptables, nftables |
| conntrack | Disable TCP window tracking ("ip_conntrack_tcp_be_liberal") | `linux24_conntrack_tcp_be_liberal` | tri-state (`''` no change, `'1'` on, `'0'` off) | `''` | iptables, nftables |
| Data | Data directory: | `linux24_data_dir` | string | `''` | iptables |
| Options | Ignore all pings | `linux24_icmp_echo_ignore_all` | tri-state (`''` no change, `'1'` on, `'0'` off) | `''` | iptables, nftables |
| Options | Ignore broadcast pings | `linux24_icmp_echo_ignore_broadcasts` | tri-state (`''` no change, `'1'` on, `'0'` off) | `''` | iptables, nftables |
| Options | Ignore bogus ICMP errors | `linux24_icmp_ignore_bogus_error_responses` | tri-state (`''` no change, `'1'` on, `'0'` off) | `''` | iptables, nftables |
| Options | Allow dynamic addresses | `linux24_ip_dynaddr` | tri-state (`''` no change, `'1'` on, `'0'` off) | `''` | iptables, nftables |
| Options | IPv4 Packet forwarding | `linux24_ip_forward` | tri-state (`''` no change, `'1'` on, `'0'` off) | `''` | iptables, nftables |
| Options | IPv6 Packet forwarding | `linux24_ipv6_forward` | tri-state (`''` no change, `'1'` on, `'0'` off) | `''` | iptables, nftables |
| Options | Log martians | `linux24_log_martians` | tri-state (`''` no change, `'1'` on, `'0'` off) | `''` | iptables, nftables |
| Path | brctl: | `linux24_path_brctl` | string | `''` | iptables |
| Path | ifenslave: | `linux24_path_ifenslave` | string | `''` | iptables |
| Path | ip: | `linux24_path_ip` | string | `''` | iptables |
| Path | ip6tables: | `linux24_path_ip6tables` | string | `''` | iptables |
| Path | ip6tables-restore: | `linux24_path_ip6tables_restore` | string | `''` | iptables |
| Path | ipset: | `linux24_path_ipset` | string | `''` | iptables |
| Path | iptables: | `linux24_path_iptables` | string | `''` | iptables |
| Path | iptables-restore: | `linux24_path_iptables_restore` | string | `''` | iptables |
| Path | logger: | `linux24_path_logger` | string | `''` | iptables |
| Path | lsmod: | `linux24_path_lsmod` | string | `''` | iptables |
| Path | modprobe: | `linux24_path_modprobe` | string | `''` | iptables |
| Path | vconfig: | `linux24_path_vconfig` | string | `''` | iptables |
| Options | Kernel anti-spoofing protection | `linux24_rp_filter` | tri-state (`''` no change, `'1'` on, `'0'` off) | `''` | iptables, nftables |
| TCP | TCP ECN | `linux24_tcp_ecn` | tri-state (`''` no change, `'1'` on, `'0'` off) | `''` | iptables, nftables |
| TCP | TCP fack | `linux24_tcp_fack` | tri-state (`''` no change, `'1'` on, `'0'` off) | `''` | iptables |
| TCP | TCP FIN timeout (sec) | `linux24_tcp_fin_timeout` | integer (`-1` = kernel default) | `-1` | iptables, nftables |
| TCP | TCP keepalive time (sec) | `linux24_tcp_keepalive_interval` | integer (`-1` = kernel default) | `-1` | iptables, nftables |
| TCP | TCP sack | `linux24_tcp_sack` | tri-state (`''` no change, `'1'` on, `'0'` off) | `''` | iptables, nftables |
| TCP | TCP SYN cookies | `linux24_tcp_syncookies` | tri-state (`''` no change, `'1'` on, `'0'` off) | `''` | iptables, nftables |
| TCP | TCP timestamps | `linux24_tcp_timestamps` | tri-state (`''` no change, `'1'` on, `'0'` off) | `''` | iptables, nftables |
| TCP | TCP window scaling | `linux24_tcp_window_scaling` | tri-state (`''` no change, `'1'` on, `'0'` off) | `''` | iptables, nftables |


### Platform settings (Firewall > Platform Settings ...)

| Tab | GUI field | YAML key (under `options:`) | Type / values | Default | Platform |
|---|---|---|---|---|---|
| Compiler | Accept ESTABLISHED and RELATED packets before the first rule | `accept_established` | on/off (`true` / `false`) | `true` | iptables, nftables |
| Compiler | Accept TCP sessions opened prior to firewall restart | `accept_new_tcp_with_no_syn` | on/off (`true` / `false`) | `true` | iptables, nftables |
| Compiler | Default action on 'Reject': | `action_on_reject` | one of: `ICMP unreachable`, `ICMP net unreachable`, `ICMP host unreachable`, `ICMP port unreachable`, `ICMP net prohibited`, `ICMP host prohibited`, `TCP RST` | `''` | iptables, nftables |
| Installer | A command that installer should execute on the firewall in order to activate the policy (if this field is blank, installer runs firewall script in the directory specified above; it uses sudo if user name is not 'root') | `activationCmd` | string | `''` | iptables, nftables |
| Installer | User name used to authenticate to the firewall | `admUser` | string | `''` | iptables, nftables |
| Installer | Alternative name or address used to communicate with the firewall | `altAddress` | string | `''` | iptables, nftables |
| Compiler | Bridging firewall | `bridging_fw` | on/off (`true` / `false`) | `false` | iptables, nftables |
| Compiler | Detect shadowing in policy rules | `check_shading` | on/off (`true` / `false`) | `true` | iptables, nftables |
| Compiler | Clamp MSS to MTU | `clamp_mss_to_mtu` | on/off (`true` / `false`) | `false` | iptables, nftables |
| Script | Clear unknown interfaces: Uses “ip addr flush” and “ip link set down” to remove IP addresses and shut down interfaces not defined in the firewall configuration. | `clear_unknown_interfaces` | on/off (`true` / `false`) | `false` | iptables, nftables |
| Compiler | Compiler command line options: | `cmdline` | string | `''` | iptables, nftables |
| Compiler | Compiler: | `compiler` | string | `''` | iptables, nftables |
| Script | Configure bridge interfaces: Creates bridge interfaces using “ip link add type bridge” and assigns member interfaces with “ip link set master”. | `configure_bridge_interfaces` | on/off (`true` / `false`) | `false` | iptables, nftables |
| Script | Configure interfaces: Uses “ip addr add” and “ip addr del” to configure IP addresses on firewall interfaces exactly as defined in the firewall object. | `configure_interfaces` | on/off (`true` / `false`) | `true` | iptables, nftables |
| Script | Turn debugging on: The generated script runs with “set -x”, causing every shell command to be printed to stderr. Warning: produces a lot of output. | `debug` | on/off (`true` / `false`) | `false` | iptables, nftables |
| Compiler | Drop packets that are associated with no known connection | `drop_invalid` | on/off (`true` / `false`) | `false` | iptables, nftables |
| Prolog/Epilog | Epilog - The following commands will be added verbatim after generated configuration | `epilog_script` | multi-line string | `''` | iptables, nftables |
| Installer | Directory on the firewall where script should be installed | `firewall_dir` | string | `/etc` | iptables, nftables |
| Compiler | Assume firewall is part of 'any' | `firewall_is_part_of_any_and_networks` | on/off (`true` / `false`) | `true` | iptables, nftables |
| Compiler | Flush entire ruleset | `flush_ruleset` | on/off (`true` / `false`) | `true` | iptables, nftables |
| Compiler | Ignore empty groups in rules | `ignore_empty_groups` | on/off (`true` / `false`) | `false` | iptables, nftables |
| Installer | Policy install script (using built-in installer if this field is blank): | `installScript` | string | `''` | iptables, nftables |
| Installer | Command line options for the script: | `installScriptArgs` | string | `''` | iptables, nftables |
| IPv6 | The order in which ipv4 and ipv6 rules should be generated: | `ipv4_6_order` | one of: `ipv4_first`, `ipv6_first` | `ipv4_first` | iptables, nftables |
| Compiler | Add rules to accept IPv6 Neighbor Discovery packets to IPv6 policies | `ipv6_neighbor_discovery` | on/off (`true` / `false`) | `false` | iptables |
| Logging | Logging limit: | `limit_suffix` | one of: `/second`, `/minute`, `/hour`, `/day` | `/second` | iptables |
| Logging | Logging limit: | `limit_value` | integer (`-1` = kernel default) | `0` | iptables |
| Script | Load iptables modules: Uses modprobe to load required netfilter kernel modules (connection tracking, NAT). Already loaded modules are skipped automatically. | `load_modules` | on/off (`true` / `false`) | `true` | iptables |
| Compiler | Enable support for NAT of locally originated connections | `local_nat` | on/off (`true` / `false`) | `false` | iptables, nftables |
| Logging | Activate logging in all rules (overrides rule options, use for debugging) | `log_all` | on/off (`true` / `false`) | `false` | iptables, nftables |
| Compiler | and log them | `log_invalid` | on/off (`true` / `false`) | `false` | iptables, nftables |
| Logging | log IP options | `log_ip_opt` | on/off (`true` / `false`) | `false` | iptables, nftables |
| Logging | Log level: | `log_level` | one of: ``, `alert`, `crit`, `debug`, `emerg`, `error`, `info`, `notice`, `warning` | `info` | iptables, nftables |
| Logging | Log prefix: | `log_prefix` | string | `RULE %N -- %A ` | iptables, nftables |
| Logging | log TCP options | `log_tcp_opt` | on/off (`true` / `false`) | `false` | iptables, nftables |
| Logging | log TCP seq. numbers | `log_tcp_seq` | on/off (`true` / `false`) | `false` | iptables, nftables |
| Script | Add virtual addresses for NAT: Automatically adds virtual IP addresses via “ip addr add” for NAT target addresses not already assigned to a firewall interface. Requires “Configure interfaces” to be enabled. | `manage_virtual_addr` | on/off (`true` / `false`) | `true` | iptables |
| Compiler | mgmt_addr | `mgmt_addr` | string | `''` | iptables, nftables |
| Compiler | Always permit ssh access from the management workstation with this address: | `mgmt_ssh` | on/off (`true` / `false`) | `false` | iptables, nftables |
| Compiler | Output file name: | `output_file` | string | `fwf.sh` | iptables, nftables |
| Prolog/Epilog | Insert prolog script | `prolog_place` | one of: `top`, `after_interfaces`, `after_flush` | `top` | iptables, nftables |
| Prolog/Epilog | Prolog - The following commands will be added verbatim on top of generated configuration | `prolog_script` | multi-line string | `''` | iptables, nftables |
| Installer | Additional command line parameters for scp | `scpArgs` | string | `''` | iptables, nftables |
| Compiler | Script name on the firewall: | `script_name_on_firewall` | string | `fwf.sh` | iptables, nftables |
| Installer | Additional command line parameters for ssh | `sshArgs` | string | `''` | iptables, nftables |
| Compiler | Table name: | `table_name` | string | `fwf` | iptables, nftables |
| Logging | cprange | `ulog_cprange` | integer (`-1` = kernel default) | `0` | iptables |
| Logging | netlink group: | `ulog_nlgroup` | integer (`-1` = kernel default) | `1` | iptables, nftables |
| Logging | queue threshold: | `ulog_qthreshold` | integer (`-1` = kernel default) | `1` | iptables |
| Logging | use NFLOG | `use_NFLOG` | on/off (`true` / `false`) | `false` | iptables, nftables |
| Script | Use iptables-restore: Loads all rules in one atomic transaction instead of calling iptables for each rule individually. | `use_iptables_restore` | on/off (`true` / `false`) | `false` | iptables |
| Compiler | Use kernel timezone instead of UTC (only available in iptables v 1.4.11 and later) | `use_kerneltz` | on/off (`true` / `false`) | `false` | iptables |
| Compiler | Use module "set" for run-time Address Table objects (module is only available in iptables v 1.4.1.1 and later) | `use_m_set` | on/off (`true` / `false`) | `false` | iptables |
| Logging | use numeric syslog levels | `use_numeric_log_levels` | on/off (`true` / `false`) | `false` | iptables |
| Script | Verify interfaces: Checks at runtime that all interfaces defined in the firewall object exist on the target machine before loading rules. The script aborts if any interface is missing. | `verify_interfaces` | on/off (`true` / `false`) | `true` | iptables, nftables |

<!-- END GENERATED firewall-options-mapping -->
