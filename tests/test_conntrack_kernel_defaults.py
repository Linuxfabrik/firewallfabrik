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

"""A conntrack limit of zero means "leave the kernel alone".

Firewall Builder writes the reason above the two lines it guards
(`OSConfigurator_linux24.cpp`): "if conntrack_max and conntrack_hashsize
are equal to 0, we do not add commands from the configlet (so the kernel
defaults are used)".  Both values are load-bearing.

`nf_conntrack_max` of 0 makes `ct_count > nf_conntrack_max` true for
every new connection (`net/netfilter/nf_conntrack_core.c`), so the box
logs "table full, dropping packet" and stops passing traffic the moment
the script runs.  `nf_conntrack_hash_resize` answers 0 with `-EINVAL`,
so that line fails outright.

A `.fwb` written by Firewall Builder carries 0 for both whenever the
administrator left the fields alone, which is why the guard matters more
than the option does.
"""

import re

import pytest

from firewallfabrik.platforms.iptables._os_configurator import OSConfigurator_linux24
from firewallfabrik.platforms.nftables._os_configurator import OSConfigurator_nft


class _Firewall:
    """The little a kernel-variable pass asks of a firewall."""

    def __init__(self, options):
        self.name = 'fw'
        self.version = ''
        self.data = {}
        self.options = dict(options)
        self.interfaces = []

    def get_option(self, key, platform=None):
        from firewallfabrik.platforms._defaults import get_option_default

        if key in self.options:
            return self.options[key]
        return get_option_default('iptables', 'linux24', key)


def _kernel_vars(configurator_cls, options):
    """The kernel-variable block of a firewall carrying *options*."""
    configurator = configurator_cls(None, _Firewall(options))
    return configurator.process_firewall_options()


@pytest.fixture(
    params=[OSConfigurator_linux24, OSConfigurator_nft],
    ids=['ipt', 'nft'],
)
def configurator_cls(request):
    return request.param


@pytest.mark.parametrize(
    ('option', 'path'),
    [
        ('linux24_conntrack_max', 'nf_conntrack_max'),
        ('linux24_conntrack_hashsize', 'parameters/hashsize'),
    ],
)
def test_zero_writes_nothing(configurator_cls, option, path):
    text = _kernel_vars(configurator_cls, {option: 0})

    assert path not in text, text


@pytest.mark.parametrize(
    ('option', 'path'),
    [
        ('linux24_conntrack_max', 'nf_conntrack_max'),
        ('linux24_conntrack_hashsize', 'parameters/hashsize'),
    ],
)
def test_minus_one_writes_nothing_either(configurator_cls, option, path):
    """Which is the value the option's own default carries."""
    text = _kernel_vars(configurator_cls, {option: -1})

    assert path not in text, text


@pytest.mark.parametrize(
    ('option', 'path'),
    [
        ('linux24_conntrack_max', 'nf_conntrack_max'),
        ('linux24_conntrack_hashsize', 'parameters/hashsize'),
    ],
)
def test_a_real_number_is_still_written(configurator_cls, option, path):
    text = _kernel_vars(configurator_cls, {option: 250000})

    assert re.search(rf'echo 250000 > \S*{re.escape(path)}', text), text
