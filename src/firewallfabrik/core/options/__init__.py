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

"""Typed option keys and schemas for firewall configuration.

This module provides:

- **StrEnum keys**: Type-safe option key names that work as dict keys
- **Dataclass schemas**: Typed defaults shared between GUI and compiler
- **Migration helpers**: Legacy key compatibility

Usage in GUI dialogs::

    from firewallfabrik.core.options import LinuxOption

    # Save with type-safe key
    opts[LinuxOption.CONNTRACK_MAX] = str(widget.value())

Usage in compiler::

    from firewallfabrik.core.options import LinuxOption

    # Read with type-safe key
    val = fw.get_option(LinuxOption.CONNTRACK_MAX, -1)

The StrEnum keys ensure that typos are caught at import time rather than
failing silently at runtime. Both the GUI and compiler use the same
enum values, guaranteeing key consistency.
"""

from firewallfabrik.core.options._keys import (
    FirewallOption,
    LinuxOption,
    RuleOption,
)
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
    'FirewallOption',
    'LinuxKernelDefaults',
    'LinuxOption',
    'LinuxPathDefaults',
    'RuleBehaviorDefaults',
    'RuleLimitDefaults',
    'RuleLoggingDefaults',
    'RuleOption',
    'get_canonical_key',
    'migrate_options',
]
