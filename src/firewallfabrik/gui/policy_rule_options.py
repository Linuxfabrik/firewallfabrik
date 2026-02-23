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

"""Pure-function helpers for building rule option display data and tooltips.

Extracted from ``policy_model.py`` — these are dict/string helpers with
no Qt or model dependencies, reusable by any module that needs to inspect
rule options.
"""

from __future__ import annotations


def build_options_display(opts, rule_set_type='Policy'):
    """Build a list of (id, label, icon_type) triples from rule options.

    Matches fwbuilder's ``PolicyModel::getRuleOptions()`` /
    ``RoutingModel::getRuleOptions()`` display logic.
    The *id* is a unique string sentinel used for per-element selection.
    """
    if not opts:
        return []
    if rule_set_type == 'Routing':
        return _build_routing_options_display(opts)
    result = []
    if opt_str(opts, 'counter_name') or opt_str(opts, 'rule_name_accounting'):
        result.append(('__opt_accounting__', 'accounting', 'Accounting'))
    if opt_bool(opts, 'classification'):
        label = opt_str(opts, 'classify_str') or 'classify'
        result.append(('__opt_classify__', label, 'Classify'))
    if opt_bool(opts, 'log'):
        result.append(('__opt_log__', 'log', 'Log'))
    if has_nondefault_options(opts):
        result.append(('__opt_options__', 'options', 'Options'))
    if opt_bool(opts, 'routing'):
        result.append(('__opt_route__', 'route', 'Route'))
    if opt_bool(opts, 'tagging'):
        result.append(('__opt_tag__', 'tag', 'TagService'))
    return result


def _build_routing_options_display(opts):
    """Build options display for Routing rules.

    Mirrors fwbuilder's ``RoutingModel::getRuleOptions()`` — only shows
    "Options" when ``no_fail`` is set (i.e. non-default).
    """
    if opt_bool(opts, 'no_fail'):
        return [('__opt_options__', 'options', 'Options')]
    return []


def has_nondefault_options(opts):
    """Check whether any non-default iptables rule options are set.

    Mirrors fwbuilder's ``isDefaultPolicyRuleOptions()`` for iptables.
    """
    if opt_int(opts, 'connlimit_value') > 0:
        return True
    if opt_bool(opts, 'connlimit_above_not'):
        return True
    if opt_int(opts, 'connlimit_masklen') > 0:
        return True
    if opt_str(opts, 'firewall_is_part_of_any_and_networks'):
        return True
    if opt_int(opts, 'hashlimit_burst') > 0:
        return True
    if opt_int(opts, 'hashlimit_expire') > 0:
        return True
    if opt_int(opts, 'hashlimit_gcinterval') > 0:
        return True
    if opt_int(opts, 'hashlimit_max') > 0:
        return True
    if opt_str(opts, 'hashlimit_name'):
        return True
    if opt_int(opts, 'hashlimit_size') > 0:
        return True
    if opt_int(opts, 'hashlimit_value') > 0:
        return True
    if opt_int(opts, 'limit_burst') > 0:
        return True
    if opt_str(opts, 'limit_suffix'):
        return True
    if opt_int(opts, 'limit_value') > 0:
        return True
    if opt_bool(opts, 'limit_value_not'):
        return True
    if opt_str(opts, 'log_level'):
        return True
    if opt_str(opts, 'log_prefix'):
        return True
    return opt_int(opts, 'ulog_nlgroup') > 1


def opt_bool(opts, key):
    """Return a boolean for *key*, coercing ``'True'``/``'False'`` strings."""
    val = opts.get(key)
    if isinstance(val, str):
        return val.lower() == 'true'
    return bool(val)


def opt_int(opts, key):
    """Return an int for *key*, or 0."""
    val = opts.get(key, 0)
    try:
        return int(val)
    except (TypeError, ValueError):
        return 0


def opt_str(opts, key):
    """Return a non-empty string for *key*, or ``''``."""
    val = opts.get(key, '')
    return str(val) if val else ''


def routing_options_tooltip(row_data):
    """Build an HTML tooltip for the Routing Options column.

    Mirrors fwbuilder's routing rule options display — only the
    ``no_fail`` flag is relevant for iptables routing rules.
    """
    opts = row_data.options or {}
    rows = []
    if opt_bool(opts, 'no_fail'):
        rows.append(('If install fails, carry on', ''))
    if not rows:
        rows.append(('Default options', ''))
    html = '<table>'
    for label, value in rows:
        html += f"<tr><th align='left'>{label}</th><td>{value}</td></tr>"
    html += '</table>'
    return html


def nat_options_tooltip(row_data):
    """Build an HTML tooltip for the NAT Options column.

    Mirrors fwbuilder's ``FWObjectPropertiesFactory::getNATRuleOptions()``.
    """
    opts = row_data.options or {}
    rows = []

    if opt_bool(opts, 'ipt_use_snat_instead_of_masq'):
        rows.append(('use SNAT instead of MASQ', ''))
    if opt_bool(opts, 'ipt_use_masq'):
        rows.append(('always use MASQUERADE', ''))
    if opt_bool(opts, 'ipt_nat_random'):
        rows.append(('random', ''))
    if opt_bool(opts, 'ipt_nat_persistent'):
        rows.append(('persistent', ''))

    # Logging (always shown, last row).
    logging_on = opt_bool(opts, 'log')
    rows.append(('Logging:', 'on' if logging_on else 'off'))

    # Format as HTML table.
    html = '<table>'
    for label, value in rows:
        html += f"<tr><th align='left'>{label}</th><td>{value}</td></tr>"
    html += '</table>'
    return html


def options_tooltip(row_data):
    """Build an HTML tooltip for the Options column.

    Mirrors fwbuilder's ``FWObjectPropertiesFactory::getPolicyRuleOptions()``.
    The stateful/stateless default depends on the action: Accept defaults to
    stateful, all other actions default to stateless.
    """
    opts = row_data.options or {}
    rows = []

    # Stateful / Stateless.
    if opt_bool(opts, 'stateless'):
        rows.append(('Stateless', ''))
    else:
        rows.append(('Stateful', ''))

    # iptables-specific options (the only platform we support).
    if opt_bool(opts, 'tagging'):
        tag_id = opt_str(opts, 'tagobject_id')
        rows.append(('Tag:', tag_id or 'yes'))

    classify = opt_str(opts, 'classify_str')
    if classify:
        rows.append(('Class:', classify))

    log_prefix = opt_str(opts, 'log_prefix')
    if log_prefix:
        rows.append(('Log prefix:', log_prefix))

    log_level = opt_str(opts, 'log_level')
    if log_level:
        rows.append(('Log level:', log_level))

    nlgroup = opt_int(opts, 'ulog_nlgroup')
    if nlgroup > 1:
        rows.append(('Netlink group:', str(nlgroup)))

    limit_val = opt_int(opts, 'limit_value')
    if limit_val > 0:
        arg = '! ' if opt_bool(opts, 'limit_value_not') else ''
        arg += str(limit_val)
        suffix = opt_str(opts, 'limit_suffix')
        if suffix:
            arg += suffix
        rows.append(('Limit value:', arg))

    limit_burst = opt_int(opts, 'limit_burst')
    if limit_burst > 0:
        rows.append(('Limit burst:', str(limit_burst)))

    connlimit = opt_int(opts, 'connlimit_value')
    if connlimit > 0:
        arg = '! ' if opt_bool(opts, 'connlimit_above_not') else ''
        arg += str(connlimit)
        rows.append(('Connlimit value:', arg))

    hashlimit_val = opt_int(opts, 'hashlimit_value')
    if hashlimit_val > 0:
        hl_name = opt_str(opts, 'hashlimit_name')
        if hl_name:
            rows.append(('Hashlimit name:', hl_name))
        arg = str(hashlimit_val)
        hl_suffix = opt_str(opts, 'hashlimit_suffix')
        if hl_suffix:
            arg += hl_suffix
        rows.append(('Hashlimit value:', arg))
        hl_burst = opt_int(opts, 'hashlimit_burst')
        if hl_burst > 0:
            rows.append(('Hashlimit burst:', str(hl_burst)))

    if opt_str(opts, 'firewall_is_part_of_any_and_networks'):
        rows.append(('Part of Any', ''))

    # Logging (always shown, last row).
    logging_on = opt_bool(opts, 'log')
    rows.append(('Logging:', 'on' if logging_on else 'off'))

    # Format as HTML table.
    html = '<table>'
    for label, value in rows:
        html += f"<tr><th align='left'>{label}</th><td>{value}</td></tr>"
    html += '</table>'
    return html
