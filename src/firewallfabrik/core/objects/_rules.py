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

"""RuleSet models (STI), Rule models (STI), and rule_elements association table."""

from __future__ import (
    annotations,  # This is needed since SQLAlchemy does not support forward references yet
)

import uuid
from typing import TYPE_CHECKING, Any

import sqlalchemy
import sqlalchemy.orm

from firewallfabrik.core.options._metadata import RULE_OPTIONS

from ._base import Base

if TYPE_CHECKING:
    from ._devices import Host


class RuleSet(Base):
    """Base class for ordered collections of rules."""

    __tablename__ = 'rule_sets'

    id: sqlalchemy.orm.Mapped[uuid.UUID] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Uuid,
        primary_key=True,
    )
    type: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String(50),
    )
    device_id: sqlalchemy.orm.Mapped[uuid.UUID] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Uuid,
        sqlalchemy.ForeignKey('devices.id'),
        nullable=False,
    )
    name: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String,
        default='',
    )
    comment: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Text,
        default='',
    )
    options: sqlalchemy.orm.Mapped[dict | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.JSON,
        default=dict,
    )
    ipv4: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean,
        default=False,
    )
    ipv6: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean,
        default=False,
    )
    top: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean,
        default=False,
    )

    device: sqlalchemy.orm.Mapped[Host] = sqlalchemy.orm.relationship(
        'Host',
        back_populates='rule_sets',
    )
    rules: sqlalchemy.orm.Mapped[list[Rule]] = sqlalchemy.orm.relationship(
        'Rule',
        back_populates='rule_set',
    )

    __mapper_args__ = {
        'polymorphic_on': 'type',
        'polymorphic_identity': 'RuleSet',
    }

    __table_args__ = (
        sqlalchemy.UniqueConstraint(
            'device_id', 'type', 'name', name='uq_rule_sets_device'
        ),
    )

    # -- Compiler helper methods --

    def matching_address_family(self, af: int) -> bool:
        """Check if this rule set should be compiled for the given address family.

        *af* is a :mod:`socket` address-family constant
        (``socket.AF_INET`` or ``socket.AF_INET6``).
        Returns True if the rule set supports the given family, or if
        both are False (meaning compile for both).
        """
        import socket

        if not self.ipv4 and not self.ipv6:
            return True
        if af == socket.AF_INET:
            return self.ipv4
        if af == socket.AF_INET6:
            return self.ipv6
        return True


class Policy(RuleSet):
    """Policy (filter) rule set."""

    __mapper_args__ = {'polymorphic_identity': 'Policy'}


class NAT(RuleSet):
    """NAT rule set."""

    __mapper_args__ = {'polymorphic_identity': 'NAT'}


class Routing(RuleSet):
    """Routing rule set."""

    __mapper_args__ = {'polymorphic_identity': 'Routing'}


class Rule(Base):
    """Base class for all rule types."""

    __tablename__ = 'rules'

    id: sqlalchemy.orm.Mapped[uuid.UUID] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Uuid,
        primary_key=True,
    )
    type: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String(50),
    )
    rule_set_id: sqlalchemy.orm.Mapped[uuid.UUID] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Uuid,
        sqlalchemy.ForeignKey('rule_sets.id'),
        nullable=False,
    )
    position: sqlalchemy.orm.Mapped[int] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer,
        default=0,
    )
    name: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String,
        default='',
    )
    comment: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Text,
        default='',
    )
    label: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String,
        default='',
    )
    rule_unique_id: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String,
        default='',
    )
    compiler_message: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String,
        default='',
    )
    fallback: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean,
        default=False,
    )
    hidden: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean,
        default=False,
    )
    negations: sqlalchemy.orm.Mapped[dict | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.JSON,
        default=dict,
    )
    policy_action: sqlalchemy.orm.Mapped[int | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, nullable=True, default=None
    )
    policy_direction: sqlalchemy.orm.Mapped[int | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, nullable=True, default=None
    )
    nat_action: sqlalchemy.orm.Mapped[int | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, nullable=True, default=None
    )
    nat_rule_type: sqlalchemy.orm.Mapped[int | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, nullable=True, default=None
    )
    routing_rule_type: sqlalchemy.orm.Mapped[int | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, nullable=True, default=None
    )
    sorted_dst_ids: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, nullable=True, default=None
    )

    # -- Typed option columns (RuleOption) --
    # Rate limiting
    opt_limit_value: sqlalchemy.orm.Mapped[int] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, default=0
    )
    opt_limit_value_not: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=False
    )
    opt_limit_suffix: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=''
    )
    opt_limit_burst: sqlalchemy.orm.Mapped[int] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, default=0
    )
    # Hashlimit
    opt_hashlimit_value: sqlalchemy.orm.Mapped[int] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, default=0
    )
    opt_hashlimit_suffix: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=''
    )
    opt_hashlimit_burst: sqlalchemy.orm.Mapped[int] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, default=0
    )
    opt_hashlimit_name: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=''
    )
    opt_hashlimit_size: sqlalchemy.orm.Mapped[int] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, default=0
    )
    opt_hashlimit_max: sqlalchemy.orm.Mapped[int] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, default=0
    )
    opt_hashlimit_expire: sqlalchemy.orm.Mapped[int] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, default=0
    )
    opt_hashlimit_gcinterval: sqlalchemy.orm.Mapped[int] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, default=0
    )
    opt_hashlimit_dstlimit: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=False
    )
    opt_hashlimit_dstip: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=False
    )
    opt_hashlimit_dstport: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=False
    )
    opt_hashlimit_srcip: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=False
    )
    opt_hashlimit_srcport: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=False
    )
    # Connlimit
    opt_connlimit_value: sqlalchemy.orm.Mapped[int] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, default=0
    )
    opt_connlimit_above_not: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=False
    )
    opt_connlimit_masklen: sqlalchemy.orm.Mapped[int] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, default=0
    )
    # Logging
    opt_log_level: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=''
    )
    opt_log_prefix: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=''
    )
    opt_ulog_nlgroup: sqlalchemy.orm.Mapped[int] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, default=0
    )
    # Rule behavior
    opt_disabled: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=False
    )
    opt_stateless: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=False
    )
    opt_ipt_continue: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=False
    )
    opt_ipt_mark_connections: sqlalchemy.orm.Mapped[bool] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=False)
    )
    opt_ipt_tee: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=False
    )
    opt_ipt_iif: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=''
    )
    opt_ipt_oif: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=''
    )
    opt_ipt_gw: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=''
    )
    # Tagging
    opt_tagging: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=False
    )
    opt_tagobject_id: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=''
    )
    opt_classify_str: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=''
    )
    # Per-rule firewall scope
    opt_firewall_is_part_of_any_and_networks: sqlalchemy.orm.Mapped[bool] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=False)
    )
    # Rule flags
    opt_log: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=False
    )
    opt_logging: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=False
    )
    opt_counter_name: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=''
    )
    opt_routing: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=False
    )
    opt_classification: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=False
    )
    opt_no_output_chain: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=False
    )
    opt_no_input_chain: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=False
    )
    opt_do_not_optimize_by_srv: sqlalchemy.orm.Mapped[bool] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=False)
    )
    opt_put_in_mangle_table: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=False
    )
    opt_ipt_branch_in_mangle: sqlalchemy.orm.Mapped[bool] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=False)
    )
    # NAT options
    opt_ipt_nat_random: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=False
    )
    opt_ipt_nat_persistent: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, default=False
    )
    # Internal compiler bookkeeping
    opt_rule_added_for_osrc_neg: sqlalchemy.orm.Mapped[bool] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=False)
    )
    opt_rule_added_for_odst_neg: sqlalchemy.orm.Mapped[bool] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=False)
    )
    opt_rule_added_for_osrv_neg: sqlalchemy.orm.Mapped[bool] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=False)
    )
    # Per-rule reject action override
    opt_action_on_reject: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=''
    )
    # Routing rule metric
    opt_metric: sqlalchemy.orm.Mapped[int] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, default=0
    )
    # Accounting and custom actions
    opt_rule_name_accounting: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=''
    )
    opt_custom_str: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, default=''
    )
    # Ruleset option (mangle table only)
    opt_mangle_only_rule_set: sqlalchemy.orm.Mapped[bool] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, default=False)
    )

    rule_set: sqlalchemy.orm.Mapped[RuleSet] = sqlalchemy.orm.relationship(
        'RuleSet',
        back_populates='rules',
    )

    __mapper_args__ = {
        'polymorphic_on': 'type',
        'polymorphic_identity': 'Rule',
    }

    __table_args__ = (
        sqlalchemy.Index('ix_rules_type', 'type'),
        sqlalchemy.Index('ix_rules_rule_set_id', 'rule_set_id'),
        sqlalchemy.Index('ix_rules_position', 'rule_set_id', 'position'),
    )

    # -- Compiler helper methods --

    @property
    def options(self) -> dict:
        """Build options dict from typed columns.

        Provides backward compatibility for code that accesses rule.options.
        Only includes non-default values.
        """
        opts = {}
        for _, meta in RULE_OPTIONS.items():
            value = getattr(self, meta.column_name)
            if value != meta.default:
                opts[meta.yaml_key] = value
        return opts

    @options.setter
    def options(self, opts: dict | None) -> None:
        """Set typed columns from an options dict.

        Used by XML reader and GUI dialogs.
        Unknown options are silently ignored for legacy XML compatibility.
        Use get_option() for strict validation when accessing options.
        """
        if not opts:
            return
        # Set values for known options only, skip unknown
        for _, meta in RULE_OPTIONS.items():
            if meta.yaml_key in opts:
                value = opts[meta.yaml_key]
                # Coerce types if needed
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
                setattr(self, meta.column_name, value)

    def get_option(self, key: str, default: Any = None) -> Any:
        """Look up an option value by enum key.

        Uses typed columns for known option keys, with automatic
        type coercion for legacy XML string values.
        """
        meta = RULE_OPTIONS.get(key)
        if meta is not None:
            value = getattr(self, meta.column_name)
            # Coerce string 'True'/'False' to bool for XML compatibility
            if isinstance(value, str):
                if value.lower() == 'true':
                    return True
                if value.lower() == 'false':
                    return False
            return value
        raise AttributeError(f'Unknown option key: {key}')


class PolicyRule(Rule):
    """Policy (filter) rule."""

    __mapper_args__ = {'polymorphic_identity': 'PolicyRule'}


class NATRule(Rule):
    """Network address translation rule."""

    __mapper_args__ = {'polymorphic_identity': 'NATRule'}


class RoutingRule(Rule):
    """Routing rule."""

    __mapper_args__ = {'polymorphic_identity': 'RoutingRule'}


rule_elements = sqlalchemy.Table(
    'rule_elements',
    Base.metadata,
    sqlalchemy.Column(
        'rule_id',
        sqlalchemy.Uuid,
        sqlalchemy.ForeignKey('rules.id'),
        primary_key=True,
    ),
    sqlalchemy.Column(
        'slot',
        sqlalchemy.String(20),
        primary_key=True,
    ),
    sqlalchemy.Column(
        'target_id',
        sqlalchemy.Uuid,
        primary_key=True,
    ),
    sqlalchemy.Column(
        'position',
        sqlalchemy.Integer,
        default=0,
    ),
    sqlalchemy.Index('ix_rule_elements_rule_id', 'rule_id'),
    sqlalchemy.Index('ix_rule_elements_slot', 'rule_id', 'slot'),
)
