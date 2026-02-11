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

"""Compiler infrastructure for firewall rule compilation."""

from ._base import BaseCompiler, CompilerStatus
from ._comp_rule import CompRule, expand_group, load_rules
from ._compiler import Compiler
from ._nat_compiler import NATCompiler
from ._os_configurator import OSConfigurator
from ._policy_compiler import PolicyCompiler
from ._preprocessor import Preprocessor
from ._routing_compiler import RoutingCompiler
from ._rule_processor import (
    BasicRuleProcessor,
    NATRuleProcessor,
    PolicyRuleProcessor,
    RoutingRuleProcessor,
)

__all__ = [
    'BaseCompiler',
    'BasicRuleProcessor',
    'CompRule',
    'Compiler',
    'CompilerStatus',
    'NATCompiler',
    'NATRuleProcessor',
    'OSConfigurator',
    'PolicyCompiler',
    'PolicyRuleProcessor',
    'Preprocessor',
    'RoutingCompiler',
    'RoutingRuleProcessor',
    'expand_group',
    'load_rules',
]
