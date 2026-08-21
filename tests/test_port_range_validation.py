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

"""A TCP or UDP service whose port range runs backwards.

Neither packet filter takes one.  iptables answers
``invalid portrange (min > max)`` for ``--dport`` and ``invalid portrange
specified`` for ``-m multiport``, which stops the activation script with
the built-in policies already at DROP; nftables answers ``Range negative
size`` and refuses the whole ruleset, so the firewall never gets the new
policy at all.  Both offered to iptables 1.8.11 and nft 1.1.6 first.

Firewall Builder corrects the value in its editor instead - its bug
#1695481, fixed in ``TCPServiceDialog::applyChanges`` and the UDP one -
and so does the FirewallFabrik editor.  A data file written by an older
release, by another tool or by hand carries whatever it carries, which is
why the compiler asks as well.
"""

import uuid

import pytest

from firewallfabrik.compiler.processors._service import port_range_problem
from firewallfabrik.core.objects import ICMPService, TCPService, UDPService


def _service(cls, **ranges):
    srv = cls(id=uuid.uuid4(), name='probe')
    for key, value in ranges.items():
        setattr(srv, key, value)
    return srv


@pytest.mark.parametrize('cls', [TCPService, UDPService])
@pytest.mark.parametrize(
    'ranges',
    [
        {'dst_range_start': 8080, 'dst_range_end': 20},
        {'src_range_start': 1024, 'src_range_end': 1023},
        {'dst_range_start': 65535, 'dst_range_end': 1},
    ],
)
def test_a_range_that_runs_backwards_is_reported(cls, ranges):
    assert port_range_problem(_service(cls, **ranges))


@pytest.mark.parametrize('cls', [TCPService, UDPService])
@pytest.mark.parametrize(
    'ranges',
    [
        # No range at all.
        {},
        # A single port: the printers write the start alone, and an end of
        # 0 means "no range" rather than "port 0".
        {'dst_range_start': 80, 'dst_range_end': 0},
        {'dst_range_start': 80, 'dst_range_end': 80},
        {'dst_range_start': 1024, 'dst_range_end': 65535},
        {'src_range_start': 1, 'src_range_end': 1024},
    ],
)
def test_a_range_both_tools_take(cls, ranges):
    assert not port_range_problem(_service(cls, **ranges))


def test_a_service_without_ports_is_not_asked():
    """Only TCP and UDP carry port ranges."""
    assert not port_range_problem(ICMPService(id=uuid.uuid4(), name='probe'))
