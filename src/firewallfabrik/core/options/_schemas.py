# Copyright (C) 2026 Linuxfabrik <info@linuxfabrik.ch>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# On Debian systems, the complete text of the GNU General Public License
# version 2 can be found in /usr/share/common-licenses/GPL-2.
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""Typed option schemas with shared defaults.

This module provides dataclass schemas that define the typed structure
and default values for firewall options. These schemas serve as the
single source of truth for:

1. What options exist and their types
2. Default values shared between GUI and compiler
3. Documentation of option semantics

The schemas are used for:
- Populating GUI dialogs with defaults
- Validating option values
- Generating documentation
"""

from dataclasses import dataclass


@dataclass
class LinuxKernelDefaults:
    """Default values for Linux kernel/sysctl options.

    These options map to /proc/sys kernel parameters on Linux.
    String values are '0', '1', or '' (no change).
    Integer values of -1 mean "use system default / no change".
    """

    # IP forwarding ('' = no change, '1' = on, '0' = off)
    ip_forward: str = ''
    ipv6_forward: str = ''

    # Network stack tuning
    rp_filter: str = ''
    accept_source_route: str = ''
    accept_redirects: str = ''
    log_martians: str = ''
    ip_dynaddr: str = ''

    # ICMP
    icmp_echo_ignore_broadcasts: str = ''
    icmp_echo_ignore_all: str = ''
    icmp_ignore_bogus_error_responses: str = ''

    # TCP tuning
    tcp_window_scaling: str = ''
    tcp_sack: str = ''
    tcp_fack: str = ''
    tcp_ecn: str = ''
    tcp_syncookies: str = ''
    tcp_timestamps: str = ''
    tcp_fin_timeout: int = -1  # -1 means no change
    tcp_keepalive_interval: int = -1

    # Conntrack (-1 means no change)
    conntrack_max: int = -1
    conntrack_hashsize: int = -1
    conntrack_tcp_be_liberal: int = -1


@dataclass
class LinuxPathDefaults:
    """Default tool paths for Linux systems."""

    iptables: str = 'iptables'
    ip6tables: str = 'ip6tables'
    iptables_restore: str = 'iptables-restore'
    ip6tables_restore: str = 'ip6tables-restore'
    ip: str = 'ip'
    logger: str = 'logger'
    vconfig: str = 'vconfig'
    brctl: str = 'brctl'
    ifenslave: str = 'ifenslave'
    modprobe: str = 'modprobe'
    lsmod: str = 'lsmod'
    ipset: str = 'ipset'
    data_dir: str = ''


@dataclass
class FirewallDefaults:
    """Default values for firewall/compiler options."""

    # Compiler behavior
    firewall_is_part_of_any_and_networks: bool = False
    accept_new_tcp_with_no_syn: bool = False
    accept_established: bool = False
    drop_invalid: bool = False
    log_invalid: bool = False
    local_nat: bool = False
    check_shading: bool = False
    ignore_empty_groups: bool = False
    clamp_mss_to_mtu: bool = False
    bridging_fw: bool = False
    ipv6_neighbor_discovery: bool = False

    # Management access
    mgmt_ssh: bool = False
    mgmt_addr: str = ''
    add_mgmt_ssh_rule_when_stoped: bool = False

    # IPset / kernel timezone
    use_m_set: bool = False
    use_kerneltz: bool = False

    # Logging
    log_tcp_seq: bool = False
    log_tcp_opt: bool = False
    log_ip_opt: bool = False
    use_numeric_log_levels: bool = False
    log_all: bool = False
    log_level: str = ''
    log_prefix: str = ''
    use_ULOG: bool = False
    use_NFLOG: bool = False
    ulog_cprange: int = 0
    ulog_qthreshold: int = 1
    ulog_nlgroup: int = 1

    # Limit/rate
    limit_value: int = 0
    limit_suffix: str = '/second'
    action_on_reject: str = 'ICMP unreachable'

    # Script generation
    load_modules: bool = False
    debug: bool = False
    verify_interfaces: bool = False
    configure_interfaces: bool = False
    clear_unknown_interfaces: bool = False
    configure_vlan_interfaces: bool = False
    configure_bridge_interfaces: bool = False
    configure_bonding_interfaces: bool = False
    manage_virtual_addr: bool = False
    use_iptables_restore: bool = False

    # Compiler paths and output
    compiler: str = ''
    cmdline: str = ''
    output_file: str = ''
    script_name_on_firewall: str = ''
    firewall_dir: str = ''
    admUser: str = ''
    altAddress: str = ''
    activationCmd: str = ''
    sshArgs: str = ''
    scpArgs: str = ''
    installScript: str = ''
    installScriptArgs: str = ''

    # Prolog/epilog
    prolog_script: str = ''
    epilog_script: str = ''
    prolog_place: str = 'top'

    # IPv4/IPv6 order
    ipv4_6_order: str = 'ipv4_first'


@dataclass
class RuleLimitDefaults:
    """Default values for rule rate limiting options."""

    # Limit match
    limit_value: int = 0
    limit_value_not: bool = False
    limit_suffix: str = '/second'
    limit_burst: int = 5

    # Hashlimit
    hashlimit_value: int = 0
    hashlimit_suffix: str = '/second'
    hashlimit_burst: int = 5
    hashlimit_name: str = ''
    hashlimit_size: int = 0
    hashlimit_max: int = 0
    hashlimit_expire: int = 0
    hashlimit_gcinterval: int = 0
    hashlimit_dstlimit: bool = False
    hashlimit_dstip: bool = False
    hashlimit_dstport: bool = False
    hashlimit_srcip: bool = False
    hashlimit_srcport: bool = False

    # Connlimit
    connlimit_value: int = 0
    connlimit_above_not: bool = False
    connlimit_masklen: int = 32


@dataclass
class RuleLoggingDefaults:
    """Default values for rule logging options."""

    log_level: str = ''
    log_prefix: str = ''
    ulog_nlgroup: int = 1


@dataclass
class RuleBehaviorDefaults:
    """Default values for rule behavior options."""

    stateless: bool = False
    ipt_continue: bool = False
    ipt_mark_connections: bool = False
    ipt_tee: bool = False
    ipt_iif: str = ''
    ipt_oif: str = ''
    ipt_gw: str = ''
    classify_str: str = ''


# Instantiate default objects for easy access
LINUX_KERNEL_DEFAULTS = LinuxKernelDefaults()
LINUX_PATH_DEFAULTS = LinuxPathDefaults()
FIREWALL_DEFAULTS = FirewallDefaults()
RULE_LIMIT_DEFAULTS = RuleLimitDefaults()
RULE_LOGGING_DEFAULTS = RuleLoggingDefaults()
RULE_BEHAVIOR_DEFAULTS = RuleBehaviorDefaults()
