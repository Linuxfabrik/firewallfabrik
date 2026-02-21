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

"""Option schemas and migration helpers for firewall configuration.

This module provides:

- **Dataclass schemas**: Typed defaults shared between GUI and compiler
- **Migration helpers**: Legacy key compatibility
"""

from firewallfabrik.core.options._migration import (
    get_canonical_key,
    migrate_options,
)
from firewallfabrik.core.options._schemas import (
    FIREWALL_DEFAULTS,
    LINUX_KERNEL_DEFAULTS,
    LINUX_PATH_DEFAULTS,
    RULE_BEHAVIOR_DEFAULTS,
    RULE_LIMIT_DEFAULTS,
    RULE_LOGGING_DEFAULTS,
    FirewallDefaults,
    LinuxKernelDefaults,
    LinuxPathDefaults,
    RuleBehaviorDefaults,
    RuleLimitDefaults,
    RuleLoggingDefaults,
)

__all__ = [
    'FIREWALL_DEFAULTS',
    'LINUX_KERNEL_DEFAULTS',
    'LINUX_PATH_DEFAULTS',
    'RULE_BEHAVIOR_DEFAULTS',
    'RULE_LIMIT_DEFAULTS',
    'RULE_LOGGING_DEFAULTS',
    'FirewallDefaults',
    'LinuxKernelDefaults',
    'LinuxPathDefaults',
    'RuleBehaviorDefaults',
    'RuleLimitDefaults',
    'RuleLoggingDefaults',
    'get_canonical_key',
    'migrate_options',
]
