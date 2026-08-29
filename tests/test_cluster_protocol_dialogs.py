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

"""The parameters of a cluster group's protocol, and who reads them.

Every key these dialogs write is read by the compiler when it builds the
rules that let a member see the other members, so the two lists have to
agree: a widget writing a key nothing reads changes nothing, and a key
the compiler reads with no widget behind it cannot be set at all.
"""

import os

import pytest

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from firewallfabrik.gui.cluster_protocol_dialogs import (
    PROTOCOL_DIALOGS,
)


@pytest.fixture(scope='module', autouse=True)
def _application():
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


@pytest.fixture(scope='module')
def compiler_source():
    import pathlib

    return pathlib.Path(
        'src/firewallfabrik/platforms/linux/_automatic_rules.py',
    ).read_text()


def test_every_linux_protocol_has_a_dialog():
    """The protocols the driver accepts, minus the one with no parameters.

    "none" is a failover group that fails over with nothing, so there is
    nothing to edit and the button stays disabled.
    """
    from firewallfabrik.driver._compiler_driver import (
        FAILOVER_PROTOCOLS,
        STATE_SYNC_PROTOCOLS,
    )

    expected = (set(FAILOVER_PROTOCOLS) | set(STATE_SYNC_PROTOCOLS)) - {'none'}
    assert set(PROTOCOL_DIALOGS) == expected


#: Two values that describe the failover daemon and not the packet
#: filter: keepalived authenticates its advertisements with the secret
#: and tells one virtual router from another by the VRID.  Nothing in the
#: generated script reads them, and Firewall Builder offers them for the
#: same reason - the cluster object is where a reader looks them up.
_NOT_FOR_THE_COMPILER = frozenset({'vrrp_secret', 'vrrp_vrid'})


@pytest.mark.parametrize('protocol', sorted(PROTOCOL_DIALOGS))
def test_every_key_the_dialog_writes_is_read_by_the_compiler(protocol, compiler_source):
    dialog_cls = PROTOCOL_DIALOGS[protocol]
    for key in dialog_cls.widget_options.values():
        if key in _NOT_FOR_THE_COMPILER:
            continue
        assert f"'{key}'" in compiler_source, key


def test_the_exempt_keys_really_are_unread():
    """Or the exemption above hides a widget that stopped working."""
    import pathlib

    for key in _NOT_FOR_THE_COMPILER:
        hits = [
            path
            for path in pathlib.Path('src/firewallfabrik/platforms').rglob('*.py')
            if f"'{key}'" in path.read_text()
        ]
        assert not hits, (key, hits)


@pytest.mark.parametrize('protocol', sorted(PROTOCOL_DIALOGS))
def test_a_value_survives_the_round_trip(protocol):
    dialog_cls = PROTOCOL_DIALOGS[protocol]
    stored = {
        'conntrack_address': '239.0.0.7',
        'conntrack_port': '4711',
        'conntrack_unicast': 'True',
        'heartbeat_address': '239.0.0.8',
        'heartbeat_port': '1694',
        'heartbeat_unicast': 'True',
        'openais_address': '239.0.0.9',
        'openais_port': '5406',
        'vrrp_over_ipsec_ah': 'True',
        'vrrp_secret': 'linuxfabrik',  # nosec B105 - the placeholder secret
        'vrrp_vrid': '42',
    }

    dialog = dialog_cls(stored)
    result = dialog.get_options()

    for key in dialog_cls.widget_options.values():
        expected = stored[key]
        if expected == 'True':
            assert result[key] is True, key
        else:
            assert result[key] == expected, key
    # Keys of the other protocols are carried through untouched.
    assert set(result) == set(stored)


@pytest.mark.parametrize('protocol', sorted(PROTOCOL_DIALOGS))
def test_a_port_that_is_not_a_number_is_repaired_rather_than_shown(protocol):
    """A spin box cannot show a word, and 0 is not a port.

    The compiler reports such a value and leaves the rules out; opening
    the dialog and pressing OK puts the protocol's own port back.
    """
    dialog_cls = PROTOCOL_DIALOGS[protocol]
    port_keys = [k for k in dialog_cls.widget_options.values() if k.endswith('_port')]
    if not port_keys:
        pytest.skip('this protocol has no port')

    dialog = dialog_cls(dict.fromkeys(port_keys, 'not-a-port'))
    result = dialog.get_options()

    for key in port_keys:
        assert result[key].isdigit()
        assert 0 < int(result[key]) <= 65535


@pytest.mark.parametrize('protocol', sorted(PROTOCOL_DIALOGS))
def test_the_default_port_is_the_one_the_compiler_falls_back_to(protocol):
    """A dialog opened on an empty group must not change what compiles."""
    from firewallfabrik.platforms.linux import _automatic_rules

    defaults = {
        'conntrack_port': _automatic_rules.CONNTRACK_DEFAULT_PORT,
        'heartbeat_port': _automatic_rules.HEARTBEAT_DEFAULT_PORT,
        'openais_port': _automatic_rules.OPENAIS_DEFAULT_PORT,
    }
    dialog_cls = PROTOCOL_DIALOGS[protocol]
    port_keys = [k for k in dialog_cls.widget_options.values() if k.endswith('_port')]
    if not port_keys:
        pytest.skip('this protocol has no port')

    result = dialog_cls({}).get_options()

    for key in port_keys:
        assert int(result[key]) == defaults[key], key
