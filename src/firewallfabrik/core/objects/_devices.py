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

"""Device models (STI): Host, Firewall, Cluster, and Interface."""

from __future__ import (
    annotations,  # This is needed since SQLAlchemy does not support forward references yet
)

import uuid
from typing import TYPE_CHECKING

import sqlalchemy
import sqlalchemy.orm

from ._base import Base
from ._types import JSONEncodedSet

if TYPE_CHECKING:
    from ._addresses import Address
    from ._database import Library
    from ._groups import Group
    from ._rules import RuleSet


class Host(Base):
    """Host object (a device with interfaces)."""

    __tablename__ = 'devices'

    id: sqlalchemy.orm.Mapped[uuid.UUID] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Uuid,
        primary_key=True,
    )
    type: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String(50),
    )
    library_id: sqlalchemy.orm.Mapped[uuid.UUID] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Uuid,
        sqlalchemy.ForeignKey('libraries.id'),
        nullable=False,
    )
    group_id: sqlalchemy.orm.Mapped[uuid.UUID | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Uuid,
        sqlalchemy.ForeignKey('groups.id'),
        nullable=True,
        default=None,
    )
    name: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String,
        default='',
    )
    comment: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Text,
        default='',
    )
    ro: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean,
        default=False,
    )
    keywords: sqlalchemy.orm.Mapped[set[str] | None] = sqlalchemy.orm.mapped_column(
        JSONEncodedSet, default=set
    )
    data: sqlalchemy.orm.Mapped[dict | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.JSON,
        default=dict,
    )
    management: sqlalchemy.orm.Mapped[dict | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.JSON,
        default=dict,
    )
    id_mapping_for_duplicate: sqlalchemy.orm.Mapped[dict | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.JSON, nullable=True, default=None)
    )

    # -- Typed data columns (promoted from data JSON dict) --
    host_platform: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, nullable=True, default=None
    )
    host_os_val: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, nullable=True, default=None
    )
    host_version: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, nullable=True, default=None
    )
    host_inactive: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=False
    )
    host_last_modified: sqlalchemy.orm.Mapped[int] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, default=0
    )
    host_last_compiled: sqlalchemy.orm.Mapped[int] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, default=0
    )
    host_last_installed: sqlalchemy.orm.Mapped[int] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, default=0
    )
    host_mac_filter_enabled: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=False
    )

    # -- Typed option columns --
    # Linux kernel options (sysctl)
    opt_ip_forward: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=''
    )
    opt_ipv6_forward: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=''
    )
    opt_rp_filter: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=''
    )
    opt_accept_source_route: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=''
    )
    opt_accept_redirects: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=''
    )
    opt_log_martians: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=''
    )
    opt_ip_dynaddr: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=''
    )
    opt_icmp_echo_ignore_broadcasts: sqlalchemy.orm.Mapped[str] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.String, default='')
    )
    opt_icmp_echo_ignore_all: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=''
    )
    opt_icmp_ignore_bogus_error_responses: sqlalchemy.orm.Mapped[str] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.String, default='')
    )
    opt_tcp_window_scaling: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=''
    )
    opt_tcp_sack: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=''
    )
    opt_tcp_fack: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=''
    )
    opt_tcp_ecn: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=''
    )
    opt_tcp_syncookies: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=''
    )
    opt_tcp_timestamps: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=''
    )
    # Linux int options
    opt_tcp_fin_timeout: sqlalchemy.orm.Mapped[int] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, default=-1
    )
    opt_tcp_keepalive_interval: sqlalchemy.orm.Mapped[int] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Integer, default=-1)
    )
    opt_conntrack_max: sqlalchemy.orm.Mapped[int] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, default=-1
    )
    opt_conntrack_hashsize: sqlalchemy.orm.Mapped[int] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, default=-1
    )
    opt_conntrack_tcp_be_liberal: sqlalchemy.orm.Mapped[int] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Integer, default=-1)
    )
    # Linux path options (nullable - None means "not set")
    opt_path_iptables: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    opt_path_ip6tables: sqlalchemy.orm.Mapped[str | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.String, default=None)
    )
    opt_path_ip: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    opt_path_logger: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    opt_path_vconfig: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    opt_path_brctl: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    opt_path_ifenslave: sqlalchemy.orm.Mapped[str | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.String, default=None)
    )
    opt_path_modprobe: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    opt_path_lsmod: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    opt_path_ifconfig: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    opt_path_ipset: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    opt_path_iptables_restore: sqlalchemy.orm.Mapped[str | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.String, default=None)
    )
    opt_path_ip6tables_restore: sqlalchemy.orm.Mapped[str | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.String, default=None)
    )
    opt_data_dir: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    opt_nft_path: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    opt_ip_path: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    # Firewall bool options (nullable - None means "not set")
    opt_firewall_is_part_of_any_and_networks: sqlalchemy.orm.Mapped[bool | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=None)
    )
    opt_accept_new_tcp_with_no_syn: sqlalchemy.orm.Mapped[bool | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=None)
    )
    opt_accept_established: sqlalchemy.orm.Mapped[bool | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=None)
    )
    opt_drop_invalid: sqlalchemy.orm.Mapped[bool | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=None
    )
    opt_log_invalid: sqlalchemy.orm.Mapped[bool | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=None
    )
    opt_local_nat: sqlalchemy.orm.Mapped[bool | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=None
    )
    opt_check_shading: sqlalchemy.orm.Mapped[bool | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=None)
    )
    opt_ignore_empty_groups: sqlalchemy.orm.Mapped[bool | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=None)
    )
    opt_clamp_mss_to_mtu: sqlalchemy.orm.Mapped[bool | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=None)
    )
    opt_bridging_fw: sqlalchemy.orm.Mapped[bool | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=None
    )
    opt_ipv6_neighbor_discovery: sqlalchemy.orm.Mapped[bool | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=None)
    )
    opt_mgmt_ssh: sqlalchemy.orm.Mapped[bool | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=None
    )
    opt_add_mgmt_ssh_rule_when_stoped: sqlalchemy.orm.Mapped[bool | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=None)
    )
    opt_use_m_set: sqlalchemy.orm.Mapped[bool | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=None
    )
    opt_use_kerneltz: sqlalchemy.orm.Mapped[bool | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=None
    )
    opt_log_tcp_seq: sqlalchemy.orm.Mapped[bool | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=None
    )
    opt_log_tcp_opt: sqlalchemy.orm.Mapped[bool | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=None
    )
    opt_log_ip_opt: sqlalchemy.orm.Mapped[bool | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=None
    )
    opt_use_numeric_log_levels: sqlalchemy.orm.Mapped[bool | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=None)
    )
    opt_log_all: sqlalchemy.orm.Mapped[bool | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=None
    )
    opt_use_ulog: sqlalchemy.orm.Mapped[bool | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=None
    )
    opt_use_nflog: sqlalchemy.orm.Mapped[bool | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=None
    )
    opt_load_modules: sqlalchemy.orm.Mapped[bool | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=None
    )
    opt_debug: sqlalchemy.orm.Mapped[bool | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=None
    )
    opt_verify_interfaces: sqlalchemy.orm.Mapped[bool | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=None)
    )
    opt_configure_interfaces: sqlalchemy.orm.Mapped[bool | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=None)
    )
    opt_clear_unknown_interfaces: sqlalchemy.orm.Mapped[bool | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=None)
    )
    opt_configure_vlan_interfaces: sqlalchemy.orm.Mapped[bool | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=None)
    )
    opt_configure_bridge_interfaces: sqlalchemy.orm.Mapped[bool | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=None)
    )
    opt_configure_bonding_interfaces: sqlalchemy.orm.Mapped[bool | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=None)
    )
    opt_manage_virtual_addr: sqlalchemy.orm.Mapped[bool | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=None)
    )
    opt_use_iptables_restore: sqlalchemy.orm.Mapped[bool | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=None)
    )
    opt_drop_new_tcp_with_no_syn: sqlalchemy.orm.Mapped[bool | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=None)
    )
    # Firewall str options (nullable - None means "not set")
    opt_mgmt_access: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    opt_mgmt_addr: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    opt_log_level: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    opt_log_prefix: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    opt_limit_suffix: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    opt_action_on_reject: sqlalchemy.orm.Mapped[str | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.String, default=None)
    )
    opt_compiler: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    opt_cmdline: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    opt_output_file: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    opt_script_name_on_firewall: sqlalchemy.orm.Mapped[str | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.String, default=None)
    )
    opt_firewall_dir: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    opt_admuser: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    opt_altaddress: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    opt_activationcmd: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    opt_sshargs: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    opt_scpargs: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    opt_installscript: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    opt_installscriptargs: sqlalchemy.orm.Mapped[str | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.String, default=None)
    )
    opt_prolog_script: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    opt_epilog_script: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    opt_prolog_place: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    opt_ipv4_6_order: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    # Firewall int options
    opt_ulog_cprange: sqlalchemy.orm.Mapped[int] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, default=0
    )
    opt_ulog_qthreshold: sqlalchemy.orm.Mapped[int] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, default=0
    )
    opt_ulog_nlgroup: sqlalchemy.orm.Mapped[int] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, default=0
    )
    opt_limit_value: sqlalchemy.orm.Mapped[int] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, default=0
    )
    # SNMP options (legacy, for XML import)
    opt_snmp_contact: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    opt_snmp_description: sqlalchemy.orm.Mapped[str | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.String, default=None)
    )
    opt_snmp_location: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    # Additional bool options
    opt_use_mac_addr: sqlalchemy.orm.Mapped[bool | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=None
    )
    opt_use_mac_addr_filter: sqlalchemy.orm.Mapped[bool | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=None)
    )
    opt_use_ip_tool: sqlalchemy.orm.Mapped[bool | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=None
    )
    opt_ipt_use_snat_instead_of_masq: sqlalchemy.orm.Mapped[bool | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=None)
    )
    opt_ipt_snat_random: sqlalchemy.orm.Mapped[bool | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=None)
    )
    opt_ipt_mangle_only_rulesets: sqlalchemy.orm.Mapped[bool | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=None)
    )
    opt_ipt_mark_prerouting: sqlalchemy.orm.Mapped[bool | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=None)
    )
    opt_log_all_dropped: sqlalchemy.orm.Mapped[bool | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=None)
    )
    opt_fallback_log: sqlalchemy.orm.Mapped[bool | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=None
    )
    opt_configure_carp_interfaces: sqlalchemy.orm.Mapped[bool | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=None)
    )
    opt_configure_pfsync_interfaces: sqlalchemy.orm.Mapped[bool | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=None)
    )
    opt_dyn_addr: sqlalchemy.orm.Mapped[bool | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=None
    )
    opt_proxy_arp: sqlalchemy.orm.Mapped[bool | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=None
    )
    opt_enable_ipv6: sqlalchemy.orm.Mapped[bool | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=None
    )
    opt_no_ipv6_default_policy: sqlalchemy.orm.Mapped[bool | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=None)
    )
    opt_add_rules_for_ipv6_neighbor_discovery: sqlalchemy.orm.Mapped[bool | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=None)
    )
    opt_firewall_is_part_of_any: sqlalchemy.orm.Mapped[bool | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=None)
    )
    # Additional str options
    opt_log_limit_suffix: sqlalchemy.orm.Mapped[str | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.String, default=None)
    )
    opt_script_env_path: sqlalchemy.orm.Mapped[str | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.String, default=None)
    )
    opt_activation: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    opt_loopback_interface: sqlalchemy.orm.Mapped[str | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.String, default=None)
    )
    opt_modules_dir: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=None
    )
    # Additional int options
    opt_log_limit_value: sqlalchemy.orm.Mapped[int] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, default=0
    )

    library: sqlalchemy.orm.Mapped[Library] = sqlalchemy.orm.relationship(
        'Library',
        back_populates='devices',
    )
    group: sqlalchemy.orm.Mapped[Group | None] = sqlalchemy.orm.relationship(
        'Group',
        back_populates='devices',
        primaryjoin='Group.id == foreign(Host.group_id)',
    )
    interfaces: sqlalchemy.orm.Mapped[list[Interface]] = sqlalchemy.orm.relationship(
        'Interface',
        back_populates='device',
    )
    rule_sets: sqlalchemy.orm.Mapped[list[RuleSet]] = sqlalchemy.orm.relationship(
        'RuleSet',
        back_populates='device',
    )

    __mapper_args__ = {
        'polymorphic_on': 'type',
        'polymorphic_identity': 'Host',
    }

    __table_args__ = (
        sqlalchemy.Index('ix_devices_type', 'type'),
        sqlalchemy.Index('ix_devices_library_id', 'library_id'),
        sqlalchemy.Index('ix_devices_group_id', 'group_id'),
        sqlalchemy.Index('ix_devices_name', 'name'),
        sqlalchemy.UniqueConstraint(
            'group_id', 'type', 'name', name='uq_devices_group'
        ),
        sqlalchemy.Index(
            'uq_devices_orphan_lib',
            'library_id',
            'type',
            'name',
            unique=True,
            sqlite_where=sqlalchemy.text('group_id IS NULL'),
        ),
    )

    @property
    def platform(self) -> str:
        return self.host_platform or ''

    @property
    def host_os(self) -> str:
        return self.host_os_val or ''

    @property
    def version(self) -> str:
        return self.host_version or ''


class Firewall(Host):
    """Firewall object."""

    __mapper_args__ = {'polymorphic_identity': 'Firewall'}


class Cluster(Firewall):
    """High-availability cluster of firewalls."""

    __mapper_args__ = {'polymorphic_identity': 'Cluster'}


class Interface(Base):
    """Network interface object."""

    __tablename__ = 'interfaces'

    id: sqlalchemy.orm.Mapped[uuid.UUID] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Uuid,
        primary_key=True,
    )
    device_id: sqlalchemy.orm.Mapped[uuid.UUID | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Uuid,
        sqlalchemy.ForeignKey('devices.id'),
        nullable=True,
        default=None,
    )
    library_id: sqlalchemy.orm.Mapped[uuid.UUID | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Uuid,
        sqlalchemy.ForeignKey('libraries.id'),
        nullable=True,
        default=None,
    )
    name: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String,
        default='',
    )
    comment: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Text,
        default='',
    )
    keywords: sqlalchemy.orm.Mapped[set[str] | None] = sqlalchemy.orm.mapped_column(
        JSONEncodedSet, default=set
    )
    data: sqlalchemy.orm.Mapped[dict | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.JSON,
        default=dict,
    )
    bcast_bits: sqlalchemy.orm.Mapped[int] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer,
        default=0,
    )
    ostatus: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean,
        default=False,
    )
    snmp_type: sqlalchemy.orm.Mapped[int] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer,
        default=0,
    )

    # -- Typed data columns (promoted from data JSON dict) --
    iface_dyn: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=False
    )
    iface_unnum: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=False
    )
    iface_label: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, nullable=True, default=None
    )
    iface_security_level: sqlalchemy.orm.Mapped[str | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.String, nullable=True, default=None)
    )
    iface_management: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=False
    )
    iface_unprotected: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=False
    )
    iface_dedicated_failover: sqlalchemy.orm.Mapped[bool] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=False)
    )

    # -- Typed option columns --
    opt_bridge_port: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=False
    )
    opt_slave: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=False
    )
    opt_type: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=''
    )
    opt_vlan_id: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=''
    )

    parent_interface_id: sqlalchemy.orm.Mapped[uuid.UUID | None] = (
        sqlalchemy.orm.mapped_column(
            sqlalchemy.Uuid,
            sqlalchemy.ForeignKey('interfaces.id'),
            nullable=True,
            default=None,
        )
    )

    device: sqlalchemy.orm.Mapped[Host | None] = sqlalchemy.orm.relationship(
        'Host',
        back_populates='interfaces',
    )
    library: sqlalchemy.orm.Mapped[Library | None] = sqlalchemy.orm.relationship(
        'Library',
        back_populates='interfaces',
    )
    parent_interface: sqlalchemy.orm.Mapped[Interface | None] = (
        sqlalchemy.orm.relationship(
            'Interface',
            remote_side='Interface.id',
            back_populates='sub_interfaces',
        )
    )
    sub_interfaces: sqlalchemy.orm.Mapped[list[Interface]] = (
        sqlalchemy.orm.relationship(
            'Interface',
            back_populates='parent_interface',
        )
    )
    addresses: sqlalchemy.orm.Mapped[list[Address]] = sqlalchemy.orm.relationship(
        'Address',
        back_populates='interface',
        primaryjoin='Interface.id == foreign(Address.interface_id)',
    )

    __table_args__ = (
        # Sub-interfaces: unique name within the same parent interface.
        # SQLite treats NULL parent_interface_id as distinct, so this only
        # constrains actual sub-interfaces.
        sqlalchemy.UniqueConstraint(
            'parent_interface_id', 'name', name='uq_interfaces_parent'
        ),
        # Top-level interfaces: unique (device_id, name) where no parent.
        sqlalchemy.Index(
            'uq_interfaces_device',
            'device_id',
            'name',
            unique=True,
            sqlite_where=sqlalchemy.text('parent_interface_id IS NULL'),
        ),
        sqlalchemy.Index(
            'uq_interfaces_standalone_lib',
            'library_id',
            'name',
            unique=True,
            sqlite_where=sqlalchemy.text('device_id IS NULL'),
        ),
    )

    def is_loopback(self) -> bool:
        return self.name == 'lo'

    def is_dynamic(self) -> bool:
        return self.iface_dyn

    def is_unnumbered(self) -> bool:
        return self.iface_unnum

    def is_regular(self) -> bool:
        return (
            not self.is_dynamic()
            and not self.is_unnumbered()
            and not self.is_bridge_port()
        )

    def is_bridge_port(self) -> bool:
        return self.opt_bridge_port

    def is_slave(self) -> bool:
        return self.opt_slave
