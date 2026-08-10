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

"""Facts about the netfilter hooks that both backends have to respect."""

from __future__ import annotations

# A packet only carries the device it came in on until the routing decision
# is made, and only carries the device it goes out on after it: netfilter
# passes NULL for the other one.  A locally generated packet never has an
# incoming device at all.  So the LOCAL_OUT and POST_ROUTING hooks cannot
# match an incoming interface and the PRE_ROUTING and LOCAL_IN hooks cannot
# match an outgoing one (the NF_HOOK calls in net/ipv4/ip_input.c and
# net/ipv4/ip_output.c pass NULL for the missing device).
#
# iptables refuses the combination outright ("Can't use --in-interface with
# POSTROUTING", netfilter iptables/xshared.c: do_parse calls
# option_test_and_reject), so the generated script stops there.  nftables
# accepts the rule and silently never matches it.  Either way the rule the
# user asked for cannot work, so report it.
NO_INBOUND_DEVICE_CHAINS = frozenset({'output', 'postrouting'})
NO_OUTBOUND_DEVICE_CHAINS = frozenset({'input', 'prerouting'})


def interface_direction_problem(chain: str, inbound: bool) -> str:
    """Return why *chain* cannot match this interface, or an empty string.

    *chain* is the built-in chain the rule ends up in, in either spelling
    (iptables writes ``POSTROUTING``, nftables ``postrouting``).  A
    user-defined chain is never checked: which hook reaches it is decided
    by the rule that jumps to it.
    """
    name = chain.lower() if chain else ''
    if inbound and name in NO_INBOUND_DEVICE_CHAINS:
        return f'a packet in the {chain} chain has no incoming interface'
    if not inbound and name in NO_OUTBOUND_DEVICE_CHAINS:
        return f'a packet in the {chain} chain has no outgoing interface yet'
    return ''


def nat_interface_problem(chain: str, has_itf_inb: bool, has_itf_outb: bool) -> str:
    """Return why *chain* cannot match a NAT rule's interfaces, or ``''``.

    A NAT rule names its interfaces in two elements of its own instead of
    carrying a direction, so it can name both at once.  Which chain it ends
    up in follows from what it translates: a source translation runs in
    postrouting, a destination translation in prerouting, and a locally
    generated one in output.  The same hook facts as in
    :func:`interface_direction_problem` then rule one of the two elements
    out.
    """
    if has_itf_inb:
        problem = interface_direction_problem(chain, inbound=True)
        if problem:
            return f'matches on the incoming interface but {problem}'
    if has_itf_outb:
        problem = interface_direction_problem(chain, inbound=False)
        if problem:
            return f'matches on the outgoing interface but {problem}'
    return ''


# The flags of an IPService that name an IPv4 header option.  "any_opt"
# stands for "carries any option at all".
_IP_OPTION_FLAGS = ('any_opt', 'lsrr', 'rr', 'rtralt', 'ssrr', 'ts')


def has_ip_options(data: dict) -> bool:
    """Whether an IPService asks for an IPv4 header option.

    The IPv4 option field has no IPv6 counterpart: IPv6 moved what used to
    be options into extension headers, and neither iptables nor nftables
    offers a match for the old field there.  A rule whose service names one
    therefore cannot be compiled for IPv6, and dropping just the condition
    would widen the rule to every packet - which is why the callers report
    it and leave the rule out of the IPv6 ruleset.
    """
    return any(str(data.get(flag)) == 'True' for flag in _IP_OPTION_FLAGS)


# Characters the nftables preprocessor and the shell both read as syntax.
# See sanitize_log_prefix below for why none of them can be escaped.
_LOG_PREFIX_DROPPED = frozenset('$`\\')


def sanitize_log_prefix(prefix: str) -> str:
    """Return *prefix* with the characters no back end can carry removed.

    A log prefix is free text, and the macros splice a rule set name and an
    interface name into it, so it can hold anything the user typed.  It then
    has to survive two grammars that both give some characters a meaning of
    their own: the nftables parser and, on iptables, the shell that runs the
    generated script.  Three kinds of character do not make it through:

    * A double quote.  nftables has no escape for it -- its scanner reads a
      quoted string as ``\\"[^"]*\\"`` (netfilter nftables src/scanner.l), so
      the first inner quote ends the string and the rest is lexed as
      syntax.  The ruleset then fails to load as a whole and the firewall
      keeps its old rules.  In the iptables script the prefix sits inside a
      shell-quoted argument, where the shell swallows the quotes and the
      logged prefix silently loses them.  Replacing it with a single quote
      keeps the text readable and identical on both platforms.
    * ``$``, a backtick and a backslash.  nftables runs the prefix through
      its own preprocessor (netfilter nftables src/parser_bison.y hands it
      to ``str_preprocess``, src/preprocess.c), which reads a ``$`` before a
      letter or an underscore as a variable reference and refuses the whole
      ruleset with "unknown identifier".  On iptables the prefix ends up in
      a double-quoted shell word, where the very same three characters are
      the shell's variable expansion, command substitution and escape -- so
      a prefix picked up from an object name could not only mangle the text
      but run a command on the firewall at activation time.  There is no
      spelling that means the literal character in both places, so they are
      dropped.
    * A control character.  Both a rule line and a shell command line end at
      a newline, and a tab or carriage return in a kernel log message only
      confuses whatever reads it.
    """
    return ''.join(
        "'" if char == '"' else char
        for char in prefix
        if char.isprintable() and char not in _LOG_PREFIX_DROPPED
    )


# Everything the REJECT target accepts after --reject-with, primary names and
# aliases, per address family (netfilter iptables extensions/libipt_REJECT.c
# and libip6t_REJECT.c, reject_table).  REJECT_parse() compares against this
# table and calls xtables_error() on anything else, which stops the whole
# activation script, so a value coming from the rule options is checked
# against it before it reaches the command line.
REJECT_TYPES_IPV4 = frozenset(
    {
        'admin-prohib',
        'host-prohib',
        'host-unreach',
        'icmp-admin-prohibited',
        'icmp-host-prohibited',
        'icmp-host-unreachable',
        'icmp-net-prohibited',
        'icmp-net-unreachable',
        'icmp-port-unreachable',
        'icmp-proto-unreachable',
        'net-prohib',
        'net-unreach',
        'port-unreach',
        'proto-unreach',
        'tcp-reset',
        'tcp-rst',
    }
)
REJECT_TYPES_IPV6 = frozenset(
    {
        'addr-unreach',
        'adm-prohibited',
        'icmp6-addr-unreachable',
        'icmp6-adm-prohibited',
        'icmp6-no-route',
        'icmp6-policy-fail',
        'icmp6-port-unreachable',
        'icmp6-reject-route',
        'no-route',
        'policy-fail',
        'port-unreach',
        'reject-route',
        'tcp-reset',
    }
)


def reject_type_token(value: str, ipv6: bool) -> str:
    """Return the iptables ``--reject-with`` token *value* stands for.

    The GUI stores a human-readable name such as "ICMP host unreachable",
    which fwbuilder maps to a token by looking for substrings
    (``PolicyCompiler_PrintRule::_printActionOnReject``).  An imported
    ``.fwb`` may instead carry the token itself.  Both go through here, so
    the two backends pick the same ICMP message for the same rule: the
    iptables printer writes the token out, the nftables one looks up the
    code nftables calls it by.

    Returns an empty string for a value neither of the two is, which
    includes fwbuilder's own placeholders "none" and "NOP"
    (``PolicyCompiler_ipt::resetActionOnReject``).
    """
    if not value:
        return ''

    if value == 'TCP RST':
        return 'tcp-reset'

    if value.startswith('ICMP') or value == 'ICMP-unreachable':
        s = value.lower()
        if ipv6:
            # IPv6 has no net/host/protocol distinction: the kernel knows
            # only address- and port-unreachable plus admin-prohibited
            # (netfilter nftables src/datatype.c, icmpv6_code_tbl).
            if 'unreachable' in s:
                if 'port' in s or 'proto' in s:
                    return 'icmp6-port-unreachable'
                return 'icmp6-addr-unreachable'
            if 'prohibited' in s:
                return 'icmp6-adm-prohibited'
        else:
            if 'unreachable' in s:
                if 'net' in s:
                    return 'icmp-net-unreachable'
                if 'port' in s:
                    return 'icmp-port-unreachable'
                if 'proto' in s:
                    return 'icmp-proto-unreachable'
                return 'icmp-host-unreachable'
            if 'prohibited' in s:
                if 'net' in s:
                    return 'icmp-net-prohibited'
                if 'admin' in s:
                    return 'icmp-admin-prohibited'
                return 'icmp-host-prohibited'

    token = value.lower()
    if token in (REJECT_TYPES_IPV6 if ipv6 else REJECT_TYPES_IPV4):
        return token

    return ''
