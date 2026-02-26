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

"""Option metadata for typed column definitions.

This module provides column metadata for option keys, mapping between:
- YAML keys (e.g., linux24_ip_forward)
- Column names (e.g., opt_ip_forward)
- Default values and Python types

The metadata enables:
1. YAML serialization/deserialization
2. Typed SQLAlchemy column generation
"""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class OptionMeta:
    """Metadata for a single option column.

    Attributes:
        yaml_key: Key used in YAML options dict
        column_name: SQLAlchemy column name (opt_xxx)
        default: Default value for the column
        col_type: Python type (bool, str, int)
        compiler_default: Fallback when value is falsy; None = no fallback
    """

    yaml_key: str
    column_name: str
    default: Any
    col_type: type
    compiler_default: Any = None


def _make_column_name(yaml_key: str) -> str:
    """Generate column name from yaml_key.

    Examples:
        'linux24_ip_forward' -> 'opt_ip_forward'
        'accept_established' -> 'opt_accept_established'
        'use_ULOG' -> 'opt_use_ulog'
    """
    name = yaml_key
    if name.startswith('linux24_'):
        name = name[8:]
    return f'opt_{name.lower()}'


def _add(
    registry: dict[str, OptionMeta],
    yaml_keys: list[str],
    default: Any,
    col_type: type,
) -> None:
    """Add multiple option entries to a registry."""
    for key in yaml_keys:
        registry[key] = OptionMeta(
            yaml_key=key,
            column_name=_make_column_name(key),
            default=default,
            col_type=col_type,
        )


# ---------------------------------------------------------------------------
# Host options (Linux kernel + Firewall options)
# ---------------------------------------------------------------------------

HOST_OPTIONS: dict[str, OptionMeta] = {}

# Linux kernel options (str values: '', '0', '1')
_add(
    HOST_OPTIONS,
    [
        'linux24_ip_forward',
        'linux24_ipv6_forward',
        'linux24_rp_filter',
        'linux24_accept_source_route',
        'linux24_accept_redirects',
        'linux24_log_martians',
        'linux24_ip_dynaddr',
        'linux24_icmp_echo_ignore_broadcasts',
        'linux24_icmp_echo_ignore_all',
        'linux24_icmp_ignore_bogus_error_responses',
        'linux24_tcp_window_scaling',
        'linux24_tcp_sack',
        'linux24_tcp_fack',
        'linux24_tcp_ecn',
        'linux24_tcp_syncookies',
        'linux24_tcp_timestamps',
    ],
    default='',
    col_type=str,
)

# Linux int options (-1 = no change)
_add(
    HOST_OPTIONS,
    [
        'linux24_tcp_fin_timeout',
        'linux24_tcp_keepalive_interval',
        'linux24_conntrack_max',
        'linux24_conntrack_hashsize',
        'linux24_conntrack_tcp_be_liberal',
    ],
    default=-1,
    col_type=int,
)

# Linux path options (str) - use None to distinguish "not set" from "set to empty"
_add(
    HOST_OPTIONS,
    [
        'linux24_path_iptables',
        'linux24_path_ip6tables',
        'linux24_path_ip',
        'linux24_path_logger',
        'linux24_path_vconfig',
        'linux24_path_brctl',
        'linux24_path_ifenslave',
        'linux24_path_modprobe',
        'linux24_path_lsmod',
        'linux24_path_ifconfig',
        'linux24_path_ipset',
        'linux24_path_iptables_restore',
        'linux24_path_ip6tables_restore',
        'linux24_data_dir',
        'nft_path',
        'ip_path',
    ],
    default=None,
    col_type=str,
)

# Firewall bool options - use None to distinguish "not set" from "explicitly false"
_add(
    HOST_OPTIONS,
    [
        'firewall_is_part_of_any_and_networks',
        'accept_new_tcp_with_no_syn',
        'accept_established',
        'drop_invalid',
        'log_invalid',
        'local_nat',
        'check_shading',
        'ignore_empty_groups',
        'clamp_mss_to_mtu',
        'bridging_fw',
        'ipv6_neighbor_discovery',
        'mgmt_ssh',
        'add_mgmt_ssh_rule_when_stoped',
        'use_m_set',
        'use_kerneltz',
        'log_tcp_seq',
        'log_tcp_opt',
        'log_ip_opt',
        'use_numeric_log_levels',
        'log_all',
        'use_ULOG',
        'use_NFLOG',
        'load_modules',
        'debug',
        'verify_interfaces',
        'configure_interfaces',
        'clear_unknown_interfaces',
        'configure_vlan_interfaces',
        'configure_bridge_interfaces',
        'configure_bonding_interfaces',
        'manage_virtual_addr',
        'use_iptables_restore',
        'drop_new_tcp_with_no_syn',
        'use_mac_addr',
        'use_mac_addr_filter',
        'use_ip_tool',
        'ipt_use_snat_instead_of_masq',
        'ipt_snat_random',
        'ipt_mangle_only_rulesets',
        'ipt_mark_prerouting',
        'log_all_dropped',
        'fallback_log',
        'configure_carp_interfaces',
        'configure_pfsync_interfaces',
        'dyn_addr',
        'proxy_arp',
        'enable_ipv6',
        'no_ipv6_default_policy',
        'add_rules_for_ipv6_neighbor_discovery',
        'firewall_is_part_of_any',
    ],
    default=None,
    col_type=bool,
)

# Firewall str options - use None to distinguish "not set" from "set to empty"
_add(
    HOST_OPTIONS,
    [
        'mgmt_access',
        'mgmt_addr',
        'log_level',
        'log_prefix',
        'limit_suffix',
        'action_on_reject',
        'compiler',
        'cmdline',
        'output_file',
        'script_name_on_firewall',
        'firewall_dir',
        'admUser',
        'altAddress',
        'activationCmd',
        'sshArgs',
        'scpArgs',
        'installScript',
        'installScriptArgs',
        'prolog_script',
        'epilog_script',
        'prolog_place',
        'ipv4_6_order',
        'log_limit_suffix',
        'script_env_path',
        'activation',
        'loopback_interface',
        'modules_dir',
    ],
    default=None,
    col_type=str,
)

# Firewall int options
_add(
    HOST_OPTIONS,
    [
        'ulog_cprange',
        'ulog_qthreshold',
        'ulog_nlgroup',
        'limit_value',
        'log_limit_value',
    ],
    default=0,
    col_type=int,
)

# SNMP options (legacy, for XML import compatibility)
_add(
    HOST_OPTIONS,
    [
        'snmp_contact',
        'snmp_description',
        'snmp_location',
    ],
    default=None,
    col_type=str,
)

# Compiler defaults for options where empty/None means "use this value".
# These are the single source of truth for both compiler fallbacks and GUI
# placeholders.
for _key, _cd in [
    ('firewall_dir', '/etc/fw'),
    ('admUser', 'root'),
    ('prolog_place', 'top'),
    ('ipv4_6_order', 'ipv4_first'),
]:
    _m = HOST_OPTIONS[_key]
    HOST_OPTIONS[_key] = OptionMeta(
        yaml_key=_m.yaml_key,
        column_name=_m.column_name,
        default=_m.default,
        col_type=_m.col_type,
        compiler_default=_cd,
    )

# Pre-built lookup: column_name -> compiler_default (only for options that
# have one).
HOST_COMPILER_DEFAULTS: dict[str, Any] = {
    m.column_name: m.compiler_default
    for m in HOST_OPTIONS.values()
    if m.compiler_default is not None
}

# ---------------------------------------------------------------------------
# Interface options
# ---------------------------------------------------------------------------

INTERFACE_OPTIONS: dict[str, OptionMeta] = {
    'bridge_port': OptionMeta(
        yaml_key='bridge_port',
        column_name='opt_bridge_port',
        default=False,
        col_type=bool,
    ),
    'slave': OptionMeta(
        yaml_key='slave',
        column_name='opt_slave',
        default=False,
        col_type=bool,
    ),
    'type': OptionMeta(
        yaml_key='type',
        column_name='opt_type',
        default='',
        col_type=str,
    ),
    'vlan_id': OptionMeta(
        yaml_key='vlan_id',
        column_name='opt_vlan_id',
        default='',
        col_type=str,
    ),
}

# ---------------------------------------------------------------------------
# Rule options
# ---------------------------------------------------------------------------

RULE_OPTIONS: dict[str, OptionMeta] = {}

# Rule int options
_add(
    RULE_OPTIONS,
    [
        'limit_value',
        'limit_burst',
        'hashlimit_value',
        'hashlimit_burst',
        'hashlimit_size',
        'hashlimit_max',
        'hashlimit_expire',
        'hashlimit_gcinterval',
        'connlimit_value',
        'connlimit_masklen',
        'ulog_nlgroup',
        'metric',
    ],
    default=0,
    col_type=int,
)

# Rule bool options
_add(
    RULE_OPTIONS,
    [
        'limit_value_not',
        'hashlimit_dstlimit',
        'hashlimit_dstip',
        'hashlimit_dstport',
        'hashlimit_srcip',
        'hashlimit_srcport',
        'connlimit_above_not',
        'disabled',
        'stateless',
        'ipt_continue',
        'ipt_mark_connections',
        'ipt_tee',
        'tagging',
        'firewall_is_part_of_any_and_networks',
        'log',
        'logging',
        'routing',
        'classification',
        'no_output_chain',
        'no_input_chain',
        'do_not_optimize_by_srv',
        'put_in_mangle_table',
        'ipt_branch_in_mangle',
        'ipt_nat_random',
        'ipt_nat_persistent',
        'rule_added_for_osrc_neg',
        'rule_added_for_odst_neg',
        'rule_added_for_osrv_neg',
        'mangle_only_rule_set',
    ],
    default=False,
    col_type=bool,
)

# Rule str options
_add(
    RULE_OPTIONS,
    [
        'limit_suffix',
        'hashlimit_suffix',
        'hashlimit_name',
        'log_level',
        'log_prefix',
        'ipt_iif',
        'ipt_oif',
        'ipt_gw',
        'tagobject_id',
        'classify_str',
        'counter_name',
        'action_on_reject',
        'rule_name_accounting',
        'custom_str',
    ],
    default='',
    col_type=str,
)


def apply_options(obj, opts: dict, options_meta: dict[str, OptionMeta]) -> None:
    """Apply a yaml-keyed options dict to an ORM object's typed columns."""
    for meta in options_meta.values():
        if meta.yaml_key in opts:
            value = opts[meta.yaml_key]
            if meta.col_type is bool:
                if isinstance(value, str):
                    value = value.lower() in ('true', '1', 'yes')
                else:
                    value = bool(value)
            elif meta.col_type is int and not isinstance(value, int):
                try:
                    value = int(value)
                except (ValueError, TypeError):
                    value = meta.default
            setattr(obj, meta.column_name, value)


def build_options_dict(obj, options_meta: dict[str, OptionMeta]) -> dict:
    """Build a yaml-keyed options dict from an ORM object's typed columns."""
    opts = {}
    for meta in options_meta.values():
        value = getattr(obj, meta.column_name)
        if value != meta.default:
            opts[meta.yaml_key] = value
    return opts


def get_host_option_columns() -> list[tuple[str, type, Any]]:
    """Return list of (column_name, col_type, default) for Host options."""
    return [(m.column_name, m.col_type, m.default) for m in HOST_OPTIONS.values()]


def get_interface_option_columns() -> list[tuple[str, type, Any]]:
    """Return list of (column_name, col_type, default) for Interface options."""
    return [(m.column_name, m.col_type, m.default) for m in INTERFACE_OPTIONS.values()]


def get_rule_option_columns() -> list[tuple[str, type, Any]]:
    """Return list of (column_name, col_type, default) for Rule options."""
    return [(m.column_name, m.col_type, m.default) for m in RULE_OPTIONS.values()]
