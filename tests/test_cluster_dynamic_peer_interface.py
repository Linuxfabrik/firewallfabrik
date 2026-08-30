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

"""A peer whose address nobody knows does not become "any" everywhere.

A cluster member's interface may get its address by DHCP.  The generated
script cannot look that address up - it belongs to another machine - so
the automatic rules have to answer the question somehow, and
``AutomaticRules_ipt`` answers it per protocol rather than once:

* The failover rules pass ``nullptr``, which is "any", because the rule
  still names the protocol and the multicast address the failover daemon
  speaks to (VRRP: IP protocol 112 to 224.0.0.18).
* The conntrack rules pass the interface, because theirs names nothing
  but a UDP port. ``checkForDynamicInterfacesOfOtherObjects`` then
  reports the rule and leaves it out, where "any source" would have
  permitted the state sync port from everywhere.

The shared helper here used to answer "any" for both.
"""

import uuid

from firewallfabrik.core.objects import Interface
from firewallfabrik.platforms.linux._automatic_rules import _other_member_interfaces


class _Group:
    def __init__(self, members):
        self._members = members

    def get_members(self):
        return self._members


class _Firewall:
    id = uuid.uuid4()


def _interface(name, device_id, dynamic):
    iface = Interface()
    iface.id = uuid.uuid4()
    iface.name = name
    iface.device_id = device_id
    iface.data = {'dyn': dynamic}
    return iface


def _group_with_a_dynamic_peer(fw):
    own = _interface('eth0', fw.id, dynamic=False)
    peer = _interface('eth0', uuid.uuid4(), dynamic=True)
    return _Group([own, peer]), own, peer


def test_a_failover_rule_names_any_source_for_a_dynamic_peer():
    fw = _Firewall()
    group, own, peer = _group_with_a_dynamic_peer(fw)
    assert peer.is_dynamic()
    assert _other_member_interfaces(group, fw, own) == [None]


def test_a_conntrack_rule_keeps_the_dynamic_peer():
    """So the dynamic-interface check reports it instead of opening the port."""
    fw = _Firewall()
    group, _own, peer = _group_with_a_dynamic_peer(fw)
    assert _other_member_interfaces(group, fw, dynamic_is_any=False) == [peer]


def test_a_peer_with_an_address_is_named_either_way():
    fw = _Firewall()
    own = _interface('eth0', fw.id, dynamic=False)
    peer = _interface('eth0', uuid.uuid4(), dynamic=False)
    group = _Group([own, peer])
    assert _other_member_interfaces(group, fw, own) == [peer]
    assert _other_member_interfaces(group, fw, own, dynamic_is_any=False) == [peer]
