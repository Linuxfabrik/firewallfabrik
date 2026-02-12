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
from typing import TYPE_CHECKING

import sqlalchemy
import sqlalchemy.orm

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
    options: sqlalchemy.orm.Mapped[dict | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.JSON,
        default=dict,
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
