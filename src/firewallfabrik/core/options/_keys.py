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

"""Canonical option key definitions using StrEnum.

This module provides type-safe option keys that are shared between the GUI
dialogs and the compiler. Using StrEnum ensures:

1. IDE autocomplete for option keys
2. Typos are caught at import time (AttributeError)
3. Keys can be used directly as dict keys (StrEnum inherits from str)
4. A single source of truth for option key names

Example:
    from firewallfabrik.core.options import LinuxOption

    # In GUI dialog:
    opts[LinuxOption.CONNTRACK_MAX] = str(widget.value())

    # In compiler:
    val = fw.get_option(LinuxOption.CONNTRACK_MAX, -1)
"""

from enum import StrEnum


class LinuxOption(StrEnum):
    """Linux host OS kernel and sysctl option keys.

    These options configure kernel parameters via sysctl and control
    interface/module loading behavior on Linux firewalls.
    """

    # IP forwarding
    IP_FORWARD = 'linux24_ip_forward'
    IPV6_FORWARD = 'linux24_ipv6_forward'

    # Network stack tuning
    RP_FILTER = 'linux24_rp_filter'
    ACCEPT_SOURCE_ROUTE = 'linux24_accept_source_route'
    ACCEPT_REDIRECTS = 'linux24_accept_redirects'
    LOG_MARTIANS = 'linux24_log_martians'
    IP_DYNADDR = 'linux24_ip_dynaddr'

    # ICMP
    ICMP_ECHO_IGNORE_BROADCASTS = 'linux24_icmp_echo_ignore_broadcasts'
    ICMP_ECHO_IGNORE_ALL = 'linux24_icmp_echo_ignore_all'
    ICMP_IGNORE_BOGUS_ERROR_RESPONSES = 'linux24_icmp_ignore_bogus_error_responses'

    # TCP tuning
    TCP_WINDOW_SCALING = 'linux24_tcp_window_scaling'
    TCP_SACK = 'linux24_tcp_sack'
    TCP_FACK = 'linux24_tcp_fack'
    TCP_ECN = 'linux24_tcp_ecn'
    TCP_SYNCOOKIES = 'linux24_tcp_syncookies'
    TCP_TIMESTAMPS = 'linux24_tcp_timestamps'
    TCP_FIN_TIMEOUT = 'linux24_tcp_fin_timeout'
    TCP_KEEPALIVE_INTERVAL = 'linux24_tcp_keepalive_interval'

    # Conntrack
    CONNTRACK_MAX = 'linux24_conntrack_max'
    CONNTRACK_HASHSIZE = 'linux24_conntrack_hashsize'
    CONNTRACK_TCP_BE_LIBERAL = 'linux24_conntrack_tcp_be_liberal'

    # Tool paths
    PATH_IPTABLES = 'linux24_path_iptables'
    PATH_IP6TABLES = 'linux24_path_ip6tables'
    PATH_IP = 'linux24_path_ip'
    PATH_LOGGER = 'linux24_path_logger'
    PATH_VCONFIG = 'linux24_path_vconfig'
    PATH_BRCTL = 'linux24_path_brctl'
    PATH_IFENSLAVE = 'linux24_path_ifenslave'
    PATH_MODPROBE = 'linux24_path_modprobe'
    PATH_LSMOD = 'linux24_path_lsmod'
    PATH_IPSET = 'linux24_path_ipset'
    PATH_IPTABLES_RESTORE = 'linux24_path_iptables_restore'
    PATH_IP6TABLES_RESTORE = 'linux24_path_ip6tables_restore'

    # Data directory
    DATA_DIR = 'linux24_data_dir'


class FirewallOption(StrEnum):
    """Firewall/platform-level compiler option keys.

    These options control compiler behavior, logging, script generation,
    and network topology assumptions.
    """

    # Compiler behavior
    FIREWALL_IS_PART_OF_ANY = 'firewall_is_part_of_any_and_networks'
    ACCEPT_NEW_TCP_WITH_NO_SYN = 'accept_new_tcp_with_no_syn'
    ACCEPT_ESTABLISHED = 'accept_established'
    DROP_INVALID = 'drop_invalid'
    LOG_INVALID = 'log_invalid'
    LOCAL_NAT = 'local_nat'
    CHECK_SHADING = 'check_shading'
    IGNORE_EMPTY_GROUPS = 'ignore_empty_groups'
    CLAMP_MSS_TO_MTU = 'clamp_mss_to_mtu'
    BRIDGING_FW = 'bridging_fw'
    IPV6_NEIGHBOR_DISCOVERY = 'ipv6_neighbor_discovery'

    # Management access
    MGMT_SSH = 'mgmt_ssh'
    MGMT_ADDR = 'mgmt_addr'
    ADD_MGMT_SSH_RULE_WHEN_STOPPED = (
        'add_mgmt_ssh_rule_when_stoped'  # Note: legacy typo
    )

    # IPset / kernel timezone
    USE_M_SET = 'use_m_set'
    USE_KERNELTZ = 'use_kerneltz'

    # Logging
    LOG_TCP_SEQ = 'log_tcp_seq'
    LOG_TCP_OPT = 'log_tcp_opt'
    LOG_IP_OPT = 'log_ip_opt'
    USE_NUMERIC_LOG_LEVELS = 'use_numeric_log_levels'
    LOG_ALL = 'log_all'
    LOG_LEVEL = 'log_level'
    LOG_PREFIX = 'log_prefix'
    USE_ULOG = 'use_ULOG'
    USE_NFLOG = 'use_NFLOG'
    ULOG_CPRANGE = 'ulog_cprange'
    ULOG_QTHRESHOLD = 'ulog_qthreshold'
    ULOG_NLGROUP = 'ulog_nlgroup'

    # Limit/rate
    LIMIT_VALUE = 'limit_value'
    LIMIT_SUFFIX = 'limit_suffix'
    ACTION_ON_REJECT = 'action_on_reject'

    # Script generation
    LOAD_MODULES = 'load_modules'
    DEBUG = 'debug'
    VERIFY_INTERFACES = 'verify_interfaces'
    CONFIGURE_INTERFACES = 'configure_interfaces'
    CLEAR_UNKNOWN_INTERFACES = 'clear_unknown_interfaces'
    CONFIGURE_VLAN_INTERFACES = 'configure_vlan_interfaces'
    CONFIGURE_BRIDGE_INTERFACES = 'configure_bridge_interfaces'
    CONFIGURE_BONDING_INTERFACES = 'configure_bonding_interfaces'
    MANAGE_VIRTUAL_ADDR = 'manage_virtual_addr'
    USE_IPTABLES_RESTORE = 'use_iptables_restore'

    # Compiler paths and output
    COMPILER = 'compiler'
    CMDLINE = 'cmdline'
    OUTPUT_FILE = 'output_file'
    SCRIPT_NAME_ON_FIREWALL = 'script_name_on_firewall'
    FIREWALL_DIR = 'firewall_dir'
    ADM_USER = 'admUser'
    ALT_ADDRESS = 'altAddress'
    ACTIVATION_CMD = 'activationCmd'
    SSH_ARGS = 'sshArgs'
    SCP_ARGS = 'scpArgs'
    INSTALL_SCRIPT = 'installScript'
    INSTALL_SCRIPT_ARGS = 'installScriptArgs'

    # Prolog/epilog
    PROLOG_SCRIPT = 'prolog_script'
    EPILOG_SCRIPT = 'epilog_script'
    PROLOG_PLACE = 'prolog_place'

    # IPv4/IPv6 order
    IPV4_6_ORDER = 'ipv4_6_order'


class RuleOption(StrEnum):
    """Per-rule option keys.

    These options are set on individual policy rules to control
    rule-specific behavior like logging, rate limiting, and routing.
    """

    # Rate limiting (limit match)
    LIMIT_VALUE = 'limit_value'
    LIMIT_VALUE_NOT = 'limit_value_not'
    LIMIT_SUFFIX = 'limit_suffix'
    LIMIT_BURST = 'limit_burst'

    # Hashlimit
    HASHLIMIT_VALUE = 'hashlimit_value'
    HASHLIMIT_SUFFIX = 'hashlimit_suffix'
    HASHLIMIT_BURST = 'hashlimit_burst'
    HASHLIMIT_NAME = 'hashlimit_name'
    HASHLIMIT_SIZE = 'hashlimit_size'
    HASHLIMIT_MAX = 'hashlimit_max'
    HASHLIMIT_EXPIRE = 'hashlimit_expire'
    HASHLIMIT_GCINTERVAL = 'hashlimit_gcinterval'
    HASHLIMIT_DSTLIMIT = 'hashlimit_dstlimit'
    HASHLIMIT_DSTIP = 'hashlimit_dstip'
    HASHLIMIT_DSTPORT = 'hashlimit_dstport'
    HASHLIMIT_SRCIP = 'hashlimit_srcip'
    HASHLIMIT_SRCPORT = 'hashlimit_srcport'

    # Connlimit
    CONNLIMIT_VALUE = 'connlimit_value'
    CONNLIMIT_ABOVE_NOT = 'connlimit_above_not'
    CONNLIMIT_MASKLEN = 'connlimit_masklen'

    # Logging
    LOG_LEVEL = 'log_level'
    LOG_PREFIX = 'log_prefix'
    ULOG_NLGROUP = 'ulog_nlgroup'

    # Rule behavior
    STATELESS = 'stateless'
    IPT_CONTINUE = 'ipt_continue'
    IPT_MARK_CONNECTIONS = 'ipt_mark_connections'
    IPT_TEE = 'ipt_tee'
    IPT_IIF = 'ipt_iif'
    IPT_OIF = 'ipt_oif'
    IPT_GW = 'ipt_gw'

    # Tagging
    TAGGING = 'tagging'
    TAGOBJECT_ID = 'tagobject_id'
    CLASSIFY_STR = 'classify_str'

    # Per-rule firewall scope override
    FIREWALL_IS_PART_OF_ANY = 'firewall_is_part_of_any_and_networks'
