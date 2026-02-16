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
- Enum keys (e.g., LinuxOption.IP_FORWARD)
- Column names (e.g., opt_ip_forward)
- YAML keys (e.g., linux24_ip_forward)
- Default values and Python types

The metadata enables:
1. YAML serialization/deserialization
2. Typed SQLAlchemy column generation
3. Compile-time validation of option access
"""

from dataclasses import dataclass
from typing import Any

from firewallfabrik.core.options._keys import (
    FirewallOption,
    InterfaceOption,
    LinuxOption,
    RuleOption,
)


@dataclass(frozen=True)
class OptionMeta:
    """Metadata for a single option column.

    Attributes:
        yaml_key: Key used in YAML options dict (same as enum value)
        column_name: SQLAlchemy column name (opt_xxx)
        default: Default value for the column
        col_type: Python type (bool, str, int)
    """

    yaml_key: str
    column_name: str
    default: Any
    col_type: type


def _make_column_name(enum_value: str) -> str:
    """Generate column name from enum value (yaml_key).

    Examples:
        'linux24_ip_forward' -> 'opt_ip_forward'
        'accept_established' -> 'opt_accept_established'
        'use_ULOG' -> 'opt_use_ulog'
    """
    # Remove linux24_ prefix if present
    name = enum_value
    if name.startswith('linux24_'):
        name = name[8:]
    # Lowercase and add opt_ prefix
    return f'opt_{name.lower()}'


# Host options (LinuxOption + FirewallOption)
# These apply to Host/Firewall/Cluster devices

HOST_OPTIONS: dict[str, OptionMeta] = {}

# Linux kernel options (str values: '', '0', '1')
for opt in [
    LinuxOption.IP_FORWARD,
    LinuxOption.IPV6_FORWARD,
    LinuxOption.RP_FILTER,
    LinuxOption.ACCEPT_SOURCE_ROUTE,
    LinuxOption.ACCEPT_REDIRECTS,
    LinuxOption.LOG_MARTIANS,
    LinuxOption.IP_DYNADDR,
    LinuxOption.ICMP_ECHO_IGNORE_BROADCASTS,
    LinuxOption.ICMP_ECHO_IGNORE_ALL,
    LinuxOption.ICMP_IGNORE_BOGUS_ERROR_RESPONSES,
    LinuxOption.TCP_WINDOW_SCALING,
    LinuxOption.TCP_SACK,
    LinuxOption.TCP_FACK,
    LinuxOption.TCP_ECN,
    LinuxOption.TCP_SYNCOOKIES,
    LinuxOption.TCP_TIMESTAMPS,
]:
    HOST_OPTIONS[opt] = OptionMeta(
        yaml_key=opt.value,
        column_name=_make_column_name(opt.value),
        default='',
        col_type=str,
    )

# Linux int options (-1 = no change)
for opt in [
    LinuxOption.TCP_FIN_TIMEOUT,
    LinuxOption.TCP_KEEPALIVE_INTERVAL,
    LinuxOption.CONNTRACK_MAX,
    LinuxOption.CONNTRACK_HASHSIZE,
    LinuxOption.CONNTRACK_TCP_BE_LIBERAL,
]:
    HOST_OPTIONS[opt] = OptionMeta(
        yaml_key=opt.value,
        column_name=_make_column_name(opt.value),
        default=-1,
        col_type=int,
    )

# Linux path options (str) - use None to distinguish "not set" from "set to empty"
for opt in [
    LinuxOption.PATH_IPTABLES,
    LinuxOption.PATH_IP6TABLES,
    LinuxOption.PATH_IP,
    LinuxOption.PATH_LOGGER,
    LinuxOption.PATH_VCONFIG,
    LinuxOption.PATH_BRCTL,
    LinuxOption.PATH_IFENSLAVE,
    LinuxOption.PATH_MODPROBE,
    LinuxOption.PATH_LSMOD,
    LinuxOption.PATH_IFCONFIG,
    LinuxOption.PATH_IPSET,
    LinuxOption.PATH_IPTABLES_RESTORE,
    LinuxOption.PATH_IP6TABLES_RESTORE,
    LinuxOption.DATA_DIR,
    LinuxOption.NFT_PATH,
    LinuxOption.IP_PATH,
]:
    HOST_OPTIONS[opt] = OptionMeta(
        yaml_key=opt.value,
        column_name=_make_column_name(opt.value),
        default=None,
        col_type=str,
    )

# Firewall bool options - use None to distinguish "not set" from "explicitly false"
for opt in [
    FirewallOption.FIREWALL_IS_PART_OF_ANY,
    FirewallOption.ACCEPT_NEW_TCP_WITH_NO_SYN,
    FirewallOption.ACCEPT_ESTABLISHED,
    FirewallOption.DROP_INVALID,
    FirewallOption.LOG_INVALID,
    FirewallOption.LOCAL_NAT,
    FirewallOption.CHECK_SHADING,
    FirewallOption.IGNORE_EMPTY_GROUPS,
    FirewallOption.CLAMP_MSS_TO_MTU,
    FirewallOption.BRIDGING_FW,
    FirewallOption.IPV6_NEIGHBOR_DISCOVERY,
    FirewallOption.MGMT_SSH,
    FirewallOption.ADD_MGMT_SSH_RULE_WHEN_STOPPED,
    FirewallOption.USE_M_SET,
    FirewallOption.USE_KERNELTZ,
    FirewallOption.LOG_TCP_SEQ,
    FirewallOption.LOG_TCP_OPT,
    FirewallOption.LOG_IP_OPT,
    FirewallOption.USE_NUMERIC_LOG_LEVELS,
    FirewallOption.LOG_ALL,
    FirewallOption.USE_ULOG,
    FirewallOption.USE_NFLOG,
    FirewallOption.LOAD_MODULES,
    FirewallOption.DEBUG,
    FirewallOption.VERIFY_INTERFACES,
    FirewallOption.CONFIGURE_INTERFACES,
    FirewallOption.CLEAR_UNKNOWN_INTERFACES,
    FirewallOption.CONFIGURE_VLAN_INTERFACES,
    FirewallOption.CONFIGURE_BRIDGE_INTERFACES,
    FirewallOption.CONFIGURE_BONDING_INTERFACES,
    FirewallOption.MANAGE_VIRTUAL_ADDR,
    FirewallOption.USE_IPTABLES_RESTORE,
    FirewallOption.DROP_NEW_TCP_WITH_NO_SYN,
    # Additional bool options
    FirewallOption.USE_MAC_ADDR,
    FirewallOption.USE_MAC_ADDR_FILTER,
    FirewallOption.USE_IP_TOOL,
    FirewallOption.IPT_USE_SNAT_INSTEAD_OF_MASQ,
    FirewallOption.IPT_SNAT_RANDOM,
    FirewallOption.IPT_MANGLE_ONLY_RULESETS,
    FirewallOption.IPT_MARK_PREROUTING,
    FirewallOption.LOG_ALL_DROPPED,
    FirewallOption.FALLBACK_LOG,
    FirewallOption.CONFIGURE_CARP_INTERFACES,
    FirewallOption.CONFIGURE_PFSYNC_INTERFACES,
    FirewallOption.DYN_ADDR,
    FirewallOption.PROXY_ARP,
    FirewallOption.ENABLE_IPV6,
    FirewallOption.NO_IPV6_DEFAULT_POLICY,
    FirewallOption.ADD_RULES_FOR_IPV6_NEIGHBOR_DISCOVERY,
    FirewallOption.FIREWALL_IS_PART_OF_ANY_OLD,
]:
    HOST_OPTIONS[opt] = OptionMeta(
        yaml_key=opt.value,
        column_name=_make_column_name(opt.value),
        default=None,
        col_type=bool,
    )

# Firewall str options - use None to distinguish "not set" from "set to empty"
for opt in [
    FirewallOption.MGMT_ACCESS,
    FirewallOption.MGMT_ADDR,
    FirewallOption.LOG_LEVEL,
    FirewallOption.LOG_PREFIX,
    FirewallOption.LIMIT_SUFFIX,
    FirewallOption.ACTION_ON_REJECT,
    FirewallOption.COMPILER,
    FirewallOption.CMDLINE,
    FirewallOption.OUTPUT_FILE,
    FirewallOption.SCRIPT_NAME_ON_FIREWALL,
    FirewallOption.FIREWALL_DIR,
    FirewallOption.ADM_USER,
    FirewallOption.ALT_ADDRESS,
    FirewallOption.ACTIVATION_CMD,
    FirewallOption.SSH_ARGS,
    FirewallOption.SCP_ARGS,
    FirewallOption.INSTALL_SCRIPT,
    FirewallOption.INSTALL_SCRIPT_ARGS,
    FirewallOption.PROLOG_SCRIPT,
    FirewallOption.EPILOG_SCRIPT,
    FirewallOption.PROLOG_PLACE,
    FirewallOption.IPV4_6_ORDER,
    # Additional str options
    FirewallOption.LOG_LIMIT_SUFFIX,
    FirewallOption.SCRIPT_ENV_PATH,
    FirewallOption.ACTIVATION,
    FirewallOption.LOOPBACK_INTERFACE,
    FirewallOption.MODULES_DIR,
]:
    HOST_OPTIONS[opt] = OptionMeta(
        yaml_key=opt.value,
        column_name=_make_column_name(opt.value),
        default=None,
        col_type=str,
    )

# Firewall int options
for opt in [
    FirewallOption.ULOG_CPRANGE,
    FirewallOption.ULOG_QTHRESHOLD,
    FirewallOption.ULOG_NLGROUP,
    FirewallOption.LIMIT_VALUE,
    FirewallOption.LOG_LIMIT_VALUE,
]:
    HOST_OPTIONS[opt] = OptionMeta(
        yaml_key=opt.value,
        column_name=_make_column_name(opt.value),
        default=0,
        col_type=int,
    )

# SNMP options (legacy, for XML import compatibility)
for opt in [
    FirewallOption.SNMP_CONTACT,
    FirewallOption.SNMP_DESCRIPTION,
    FirewallOption.SNMP_LOCATION,
]:
    HOST_OPTIONS[opt] = OptionMeta(
        yaml_key=opt.value,
        column_name=_make_column_name(opt.value),
        default=None,
        col_type=str,
    )

# Interface options
INTERFACE_OPTIONS: dict[str, OptionMeta] = {
    InterfaceOption.BRIDGE_PORT: OptionMeta(
        yaml_key=InterfaceOption.BRIDGE_PORT.value,
        column_name='opt_bridge_port',
        default=False,
        col_type=bool,
    ),
    InterfaceOption.SLAVE: OptionMeta(
        yaml_key=InterfaceOption.SLAVE.value,
        column_name='opt_slave',
        default=False,
        col_type=bool,
    ),
    InterfaceOption.TYPE: OptionMeta(
        yaml_key=InterfaceOption.TYPE.value,
        column_name='opt_type',
        default='',
        col_type=str,
    ),
    InterfaceOption.VLAN_ID: OptionMeta(
        yaml_key=InterfaceOption.VLAN_ID.value,
        column_name='opt_vlan_id',
        default='',
        col_type=str,
    ),
}

# Rule options
RULE_OPTIONS: dict[str, OptionMeta] = {}

# Rule int options
for opt in [
    RuleOption.LIMIT_VALUE,
    RuleOption.LIMIT_BURST,
    RuleOption.HASHLIMIT_VALUE,
    RuleOption.HASHLIMIT_BURST,
    RuleOption.HASHLIMIT_SIZE,
    RuleOption.HASHLIMIT_MAX,
    RuleOption.HASHLIMIT_EXPIRE,
    RuleOption.HASHLIMIT_GCINTERVAL,
    RuleOption.CONNLIMIT_VALUE,
    RuleOption.CONNLIMIT_MASKLEN,
    RuleOption.ULOG_NLGROUP,
    RuleOption.METRIC,
]:
    RULE_OPTIONS[opt] = OptionMeta(
        yaml_key=opt.value,
        column_name=_make_column_name(opt.value),
        default=0,
        col_type=int,
    )

# Rule bool options
for opt in [
    RuleOption.LIMIT_VALUE_NOT,
    RuleOption.HASHLIMIT_DSTLIMIT,
    RuleOption.HASHLIMIT_DSTIP,
    RuleOption.HASHLIMIT_DSTPORT,
    RuleOption.HASHLIMIT_SRCIP,
    RuleOption.HASHLIMIT_SRCPORT,
    RuleOption.CONNLIMIT_ABOVE_NOT,
    RuleOption.DISABLED,
    RuleOption.STATELESS,
    RuleOption.IPT_CONTINUE,
    RuleOption.IPT_MARK_CONNECTIONS,
    RuleOption.IPT_TEE,
    RuleOption.TAGGING,
    RuleOption.FIREWALL_IS_PART_OF_ANY,
    RuleOption.LOG,
    RuleOption.LOGGING,
    RuleOption.ROUTING,
    RuleOption.CLASSIFICATION,
    RuleOption.NO_OUTPUT_CHAIN,
    RuleOption.NO_INPUT_CHAIN,
    RuleOption.DO_NOT_OPTIMIZE_BY_SRV,
    RuleOption.PUT_IN_MANGLE_TABLE,
    RuleOption.IPT_BRANCH_IN_MANGLE,
    RuleOption.IPT_NAT_RANDOM,
    RuleOption.IPT_NAT_PERSISTENT,
    RuleOption.RULE_ADDED_FOR_OSRC_NEG,
    RuleOption.RULE_ADDED_FOR_ODST_NEG,
    RuleOption.RULE_ADDED_FOR_OSRV_NEG,
    RuleOption.MANGLE_ONLY_RULE_SET,
]:
    RULE_OPTIONS[opt] = OptionMeta(
        yaml_key=opt.value,
        column_name=_make_column_name(opt.value),
        default=False,
        col_type=bool,
    )

# Rule str options
for opt in [
    RuleOption.LIMIT_SUFFIX,
    RuleOption.HASHLIMIT_SUFFIX,
    RuleOption.HASHLIMIT_NAME,
    RuleOption.LOG_LEVEL,
    RuleOption.LOG_PREFIX,
    RuleOption.IPT_IIF,
    RuleOption.IPT_OIF,
    RuleOption.IPT_GW,
    RuleOption.TAGOBJECT_ID,
    RuleOption.CLASSIFY_STR,
    RuleOption.COUNTER_NAME,
    RuleOption.ACTION_ON_REJECT,
    RuleOption.RULE_NAME_ACCOUNTING,
    RuleOption.CUSTOM_STR,
]:
    RULE_OPTIONS[opt] = OptionMeta(
        yaml_key=opt.value,
        column_name=_make_column_name(opt.value),
        default='',
        col_type=str,
    )


def get_host_option_columns() -> list[tuple[str, type, Any]]:
    """Return list of (column_name, col_type, default) for Host options."""
    return [(m.column_name, m.col_type, m.default) for m in HOST_OPTIONS.values()]


def get_interface_option_columns() -> list[tuple[str, type, Any]]:
    """Return list of (column_name, col_type, default) for Interface options."""
    return [(m.column_name, m.col_type, m.default) for m in INTERFACE_OPTIONS.values()]


def get_rule_option_columns() -> list[tuple[str, type, Any]]:
    """Return list of (column_name, col_type, default) for Rule options."""
    return [(m.column_name, m.col_type, m.default) for m in RULE_OPTIONS.values()]
