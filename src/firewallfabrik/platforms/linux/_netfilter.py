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


def sanitize_log_prefix(prefix: str) -> str:
    """Return *prefix* with the characters no back end can carry removed.

    A log prefix is free text, and the macros splice a rule set name and an
    interface name into it, so it can hold anything the user typed.  Two
    kinds of character do not survive the trip:

    * A double quote.  nftables has no escape for it -- its scanner reads a
      quoted string as ``\\"[^"]*\\"`` (netfilter nftables src/scanner.l), so
      the first inner quote ends the string and the rest is lexed as
      syntax.  The ruleset then fails to load as a whole and the firewall
      keeps its old rules.  In the iptables script the prefix sits inside a
      shell-quoted argument, where the shell swallows the quotes and the
      logged prefix silently loses them.  Replacing it with a single quote
      keeps the text readable and identical on both platforms.
    * A control character.  Both a rule line and a shell command line end at
      a newline, and a tab or carriage return in a kernel log message only
      confuses whatever reads it.
    """
    return ''.join(
        "'" if char == '"' else char for char in prefix if char.isprintable()
    )
