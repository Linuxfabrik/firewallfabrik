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
