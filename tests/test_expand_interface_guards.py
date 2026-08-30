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

"""An interface that says it has no address contributes none.

``Compiler::_expand_interface`` guards against two kinds twice over: a
bridge port is skipped while it walks the sub-interfaces, and an
unnumbered interface contributes no ``Address`` child at all
(``if (!iface->isUnnumbered() && ...)``).  Both may still *hold* an
address in the data file, because the editors write the flag without
removing what is there.

The guard belongs in the expansion and not in its callers: the branch
that expands a Host or a Firewall object walks a flat list of every
interface the device has, so a rule naming the firewall would otherwise
match an address the administrator said the interface does not answer on.
"""

import uuid

import pytest

from firewallfabrik.compiler._compiler import Compiler
from firewallfabrik.core.objects import IPv4, Interface


def _interface(*, options=None, **flags):
    iface = Interface()
    iface.id = uuid.uuid4()
    iface.name = 'eth0'
    iface.data = dict(flags)
    iface.options = dict(options or {})
    address = IPv4()
    address.id = uuid.uuid4()
    address.name = 'eth0:ip'
    address.inet_addr_mask = {'address': '192.0.2.1', 'netmask': '255.255.255.0'}
    iface.addresses = [address]
    return iface


@pytest.fixture()
def compiler():
    comp = Compiler.__new__(Compiler)
    comp.ipv6_policy = False
    return comp


def test_a_regular_interface_contributes_its_address(compiler):
    expanded = compiler._expand_interface(_interface(), use_mac=False)
    assert [a.get_address() for a in expanded] == ['192.0.2.1']


@pytest.mark.parametrize(
    'kind',
    [
        # "unnumbered" is a plain attribute of the interface element ...
        {'unnum': True},
        # ... a bridge port is an option, and normally follows from the
        # parent being a bridge.
        {'options': {'bridge_port': True}},
    ],
)
def test_an_interface_with_no_address_of_its_own_contributes_nothing(compiler, kind):
    iface = _interface(**kind)
    assert compiler._expand_interface(iface, use_mac=False) == []


def test_a_dynamic_interface_still_contributes_itself(compiler):
    """Its addresses are looked up while the generated script runs."""
    iface = _interface(dyn=True)
    assert compiler._expand_interface(iface, use_mac=False) == [iface]
