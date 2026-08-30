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

"""An option the schema calls a boolean is read the way `getBool` reads it.

A data file stores every option as a string, and both spellings of a
boolean are in the wild: Firewall Builder wrote a checkbox as
``True``/``False`` and later versions of some of the same fields as
``0``/``1``.  ``FWObject::getBool`` answers True for ``1`` and any
capitalisation of ``true`` and False for everything else - and ``'0'`` is
True in Python, so a reader taking the string as it comes reads that
option as its own opposite.

The type comes from `platforms/*/defaults.yaml`, which is the only place
that says what an option is.  A tri-state kernel toggle and a numeric
limit keep their string, because ``0`` means something to both.
"""

import uuid

import pytest

from firewallfabrik.core.objects import Firewall
from firewallfabrik.platforms._defaults import get_option_type


@pytest.fixture
def firewall():
    fw = Firewall(id=uuid.uuid4(), name='fw')
    fw.data = {'platform': 'iptables', 'host_OS': 'linux24'}
    return fw


@pytest.mark.parametrize(
    ('stored', 'expected'),
    [
        ('1', True),
        ('True', True),
        ('true', True),
        ('\n True \n', True),
        (True, True),
        ('0', False),
        ('False', False),
        ('', False),
        ('yes', False),
        (False, False),
    ],
)
def test_a_boolean_option_reads_the_way_getbool_reads_it(firewall, stored, expected):
    firewall.options = {'bridging_fw': stored}
    assert firewall.get_option('bridging_fw') is expected


def test_a_tristate_keeps_its_string(firewall):
    """`0` is "off" and `''` is "leave the kernel alone" - three states."""
    for stored in ('0', '1', ''):
        firewall.options = {'linux24_ip_forward': stored}
        assert firewall.get_option('linux24_ip_forward') == stored


def test_a_number_keeps_its_value(firewall):
    """A conntrack limit of 0 is a number, not "off"."""
    firewall.options = {'linux24_conntrack_max': '0'}
    assert firewall.get_option('linux24_conntrack_max') == '0'


def test_a_string_keeps_its_spaces(firewall):
    """A log prefix ends in a space on purpose."""
    firewall.options = {'log_prefix': 'RULE %N -- %A '}
    assert firewall.get_option('log_prefix') == 'RULE %N -- %A '


def test_the_platform_the_driver_names_decides(firewall):
    """A `.fwb` firewall says iptables whatever it is compiled with."""
    firewall.options = {'use_NFLOG': '0'}
    assert firewall.get_option('use_NFLOG', 'nftables') is False


def test_a_platform_without_a_schema_answers_nothing():
    """A `.fwb` may name any platform Firewall Builder compiles for.

    Reading an option off such a firewall - which the object tree and the
    editor do - must not depend on a compiler being there for it.
    """
    assert get_option_type('ipcop', 'linux24', 'bridging_fw') == ''
    fw = Firewall(id=uuid.uuid4(), name='fw')
    fw.data = {'platform': 'ipcop', 'host_OS': 'linux24'}
    fw.options = {'bridging_fw': 'True'}
    assert fw.get_option('bridging_fw') is True
