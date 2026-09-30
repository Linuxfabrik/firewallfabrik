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

"""The connection tracking helpers a TCP or UDP service can ask for.

Since kernel 4.7 no helper is attached to a connection on its own
(netfilter commit 3bb398d925ec), and since 6.0 there is no switch left to
turn that back on (b118509076b3): a connection gets a helper only where a
rule assigns one, with the CT target on iptables and `ct helper set` on
nftables.  A service names the helper in ``data['conntrack_helper']``, and
a rule that accepts the service assigns it.

Every helper the kernel registers is listed here, with the reason it is
offered or left out (net/netfilter/nf_conntrack_*.c,
``nf_ct_helper_init``):

* amanda, ftp, irc, netbios-ns, pptp, Q.931, RAS, sane, sip, tftp - offered.
  The name is what the kernel registers and what both tools expect.
* H.245 - left out: no rule assigns it, Q.931 attaches it to the
  connections it expects.
* snmp - left out: it only rewrites the payload when the SNMP traffic is
  NATed (nf_nat_snmp_basic), and filtering gains nothing from it.

The families are the ones ``nf_ct_helper_init`` is called with: irc,
netbios-ns and pptp register for IPv4 only.  The kernel loads the
conntrack module on its own when a rule names the helper (every module
declares ``MODULE_ALIAS_NFCT_HELPER``), but not the NAT module that
rewrites the addresses in the payload, which firewalld loads next to it
as well (src/firewall/core/fw_policy.py).
"""

from __future__ import annotations

import dataclasses


@dataclasses.dataclass(frozen=True)
class ConntrackHelper:
    """One helper: what it is called, what it tracks, what it needs."""

    name: str
    protocols: tuple[str, ...]
    ipv4: bool
    ipv6: bool
    module: str
    nat_module: str
    # Why a rule should think twice, from "Secure use of iptables and
    # connection tracking helpers" (Leblond, Neira Ayuso, McHardy,
    # Engelhardt), or empty.
    caution: str = ''


HELPERS: dict[str, ConntrackHelper] = {
    helper.name: helper
    for helper in (
        ConntrackHelper(
            'amanda', ('udp',), True, True, 'nf_conntrack_amanda', 'nf_nat_amanda'
        ),
        ConntrackHelper('ftp', ('tcp',), True, True, 'nf_conntrack_ftp', 'nf_nat_ftp'),
        ConntrackHelper(
            'irc',
            ('tcp',),
            True,
            False,
            'nf_conntrack_irc',
            'nf_nat_irc',
            'IRC DCC lets any source address connect to the client',
        ),
        ConntrackHelper(
            'netbios-ns', ('udp',), True, False, 'nf_conntrack_netbios_ns', ''
        ),
        ConntrackHelper(
            'pptp',
            ('tcp',),
            True,
            False,
            'nf_conntrack_pptp',
            'nf_nat_pptp',
            'PPTP is cryptographically broken',
        ),
        ConntrackHelper(
            'Q.931', ('tcp',), True, True, 'nf_conntrack_h323', 'nf_nat_h323'
        ),
        ConntrackHelper(
            'RAS', ('udp',), True, True, 'nf_conntrack_h323', 'nf_nat_h323'
        ),
        ConntrackHelper('sane', ('tcp',), True, True, 'nf_conntrack_sane', ''),
        ConntrackHelper(
            'sip', ('tcp', 'udp'), True, True, 'nf_conntrack_sip', 'nf_nat_sip'
        ),
        ConntrackHelper(
            'tftp', ('udp',), True, True, 'nf_conntrack_tftp', 'nf_nat_tftp'
        ),
    )
}


def helpers_for_protocol(protocol: str) -> list[str]:
    """Return the names of the helpers a *protocol* service can ask for."""
    return sorted(
        (name for name, helper in HELPERS.items() if protocol in helper.protocols),
        key=str.lower,
    )


def service_helper(service) -> str:
    """Return the helper a TCP or UDP service asks for, or an empty string."""
    return str((service.data or {}).get('conntrack_helper') or '')


def helpers_used(session, rule_sets) -> set[str]:
    """Return the helpers the accepting rules of *rule_sets* assign.

    The automatic rules at the top of the filter chains have to know it
    before any rule set is compiled: they send the RELATED connections of
    exactly these helpers through the chain that accepts them per rule,
    and branch rule sets are compiled after the top one.  Disabled rules,
    rules that accept nothing and negated service elements assign nothing,
    the way ``SplitHelperAssignment`` decides it.
    """
    from firewallfabrik.compiler._comp_rule import expand_group, load_rules
    from firewallfabrik.core.objects import (
        Group,
        PolicyAction,
        TCPService,
        UDPService,
    )

    found: set[str] = set()
    for rule_set in rule_sets:
        for rule in load_rules(session, rule_set):
            if rule.disabled or rule.action != PolicyAction.Accept:
                continue
            if rule.get_neg('srv'):
                continue
            for obj in rule.srv:
                members = (
                    expand_group(session, obj) if isinstance(obj, Group) else [obj]
                )
                for srv in members:
                    if isinstance(srv, (TCPService, UDPService)):
                        helper = service_helper(srv)
                        if helper in HELPERS:
                            found.add(helper)
    return found


def nat_helper_modules(names) -> str:
    """Return the NAT modules of the helpers *names*, for the script to load.

    Space separated and sorted, so that the generated script does not
    change with the order the rules name them in.
    """
    modules = {HELPERS[name].nat_module for name in names if name in HELPERS}
    return ' '.join(sorted(module for module in modules if module))


def anti_spoofing_warning(fw, helpers, have_ipv4, have_ipv6) -> str:
    """Return a warning when helpers are in use without reverse path filtering.

    A helper trusts the addresses it reads from the packets, so the
    netfilter developers make anti-spoofing a precondition of using one
    ("Secure use of iptables and connection tracking helpers").  The
    reverse path filter of the host settings is that protection: the
    kernel's rp_filter for IPv4, the script's own filter for IPv6.  A
    host OS fwf has no defaults for counts as unset.
    """
    if not helpers:
        return ''

    def option(key):
        try:
            return str(fw.get_option(key) or '')
        except (KeyError, ModuleNotFoundError):
            return ''

    missing = []
    if have_ipv4 and option('linux24_rp_filter') not in ('1', '2'):
        missing.append('IPv4')
    if have_ipv6 and option('linux24_ipv6_rpfilter') not in ('1', '2'):
        missing.append('IPv6')
    if not missing:
        return ''
    return (
        'Rules assign connection tracking helpers, which trust the addresses '
        'they read from packets, but the reverse path filter is off for '
        + ' and '.join(missing)
        + '; turn it on in the host settings'
    )
