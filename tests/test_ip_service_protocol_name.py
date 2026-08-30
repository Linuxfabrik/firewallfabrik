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

"""An IP Service answers with a protocol name where Firewall Builder has one.

``IPService::getProtocolName`` looks the stored number up in
``IPService::named_protocols`` - 0 is "ip", 1 "icmp", 6 "tcp", 17 "udp" -
and answers with the number for everything else (libfwbuilder
IPService.cpp).

The name is not decoration.  ``splitServicesIfRejectWithTCPReset`` asks
whether a service is TCP by protocol *name*, so an IP Service naming
protocol 6 is a TCP service there; reading it as "6" takes the TCP reset
off a Reject rule and warns instead.  ``_printProtocol`` then turns "ip"
into "all" and leaves that out of an ip6tables command, where it matches
everything and used to draw a warning from the tool.
"""

import uuid

from firewallfabrik.compiler.processors._service import ip_protocol_problem
from firewallfabrik.core.objects import IPService


def _ip_service(protocol_num):
    srv = IPService(id=uuid.uuid4(), name='proto')
    srv.named_protocols = {'protocol_num': protocol_num}
    return srv


def test_the_four_numbers_firewall_builder_names():
    assert _ip_service(0).get_protocol_name() == 'ip'
    assert _ip_service(1).get_protocol_name() == 'icmp'
    assert _ip_service(6).get_protocol_name() == 'tcp'
    assert _ip_service(17).get_protocol_name() == 'udp'


def test_every_other_number_stays_a_number():
    assert _ip_service(50).get_protocol_name() == '50'
    assert _ip_service(112).get_protocol_name() == '112'


def test_the_number_is_still_the_number():
    """`get_protocol_number` and the checks read the stored value."""
    assert _ip_service(1).get_protocol_number() == 1
    assert _ip_service(1).get_stored_protocol() == '1'
    # The check that asks whether the stored value is a protocol number at
    # all has to read it unmapped, or "icmp" reads as "not a number".
    assert ip_protocol_problem(_ip_service(1)) == ''
    assert ip_protocol_problem(_ip_service(6)) == ''
    assert 'one byte' in ip_protocol_problem(_ip_service(300))
