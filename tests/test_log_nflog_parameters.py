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

"""The other two NFLOG numbers, and how differently the two tools read them.

``--nflog-size`` is ``XTTYPE_UINT32`` and ``--nflog-threshold`` is
``XTTYPE_UINT16`` (netfilter iptables extensions/libxt_NFLOG.c); nftables
keeps the same two as ``snaplen`` and ``queue-threshold``.  Verified
against iptables 1.8.11 and nft 1.1.6:

    iptables -j NFLOG --nflog-group 5 --nflog-threshold 70000
    -> NFLOG: bad value for option "--nflog-threshold", or out of range
       (0-65535)
    nft ... log group 5 queue-threshold 70000 snaplen 5000000000
    -> accepted, and listed back as
       log group 5 snaplen 705032704 queue-threshold 4464

So iptables stops the activation script with the built-in policies
already at DROP, while nftables truncates and the copy range or the
batching silently becomes something else.  The netlink group next door
has been asked this question since it got a validator; these two are the
same field one setting over.
"""

import pytest

from firewallfabrik.platforms.linux._netfilter import (
    get_log_copy_range,
    get_log_queue_threshold,
)


class _Firewall:
    def __init__(self, values) -> None:
        self.values = values

    def get_option(self, key, default=None):
        return self.values.get(key, '')


class _Compiler:
    def __init__(self, **values) -> None:
        self.fw = _Firewall(values)
        self.warnings: list[str] = []

    def warning(self, rule_or_msg, msg: str | None = None) -> None:
        self.warnings.append(rule_or_msg if msg is None else msg)


@pytest.mark.parametrize('value', ['4294967296', '5000000000', '-1', 'abc'])
def test_a_copy_range_neither_tool_takes_is_reported_and_left_out(value):
    compiler = _Compiler(ulog_cprange=value)
    assert get_log_copy_range(compiler) == 0
    assert compiler.warnings


@pytest.mark.parametrize('value', ['0', '1500', '4294967295', 1500])
def test_a_copy_range_both_tools_take(value):
    compiler = _Compiler(ulog_cprange=value)
    assert get_log_copy_range(compiler) == int(value)
    assert compiler.warnings == []


@pytest.mark.parametrize('value', ['65536', '70000', '-1', 'abc'])
def test_a_queue_threshold_neither_tool_takes_is_reported_and_left_out(value):
    compiler = _Compiler(ulog_qthreshold=value)
    assert get_log_queue_threshold(compiler) == 1
    assert compiler.warnings


@pytest.mark.parametrize('value', ['0', '1', '50', '65535', 10])
def test_a_queue_threshold_both_tools_take(value):
    compiler = _Compiler(ulog_qthreshold=value)
    assert get_log_queue_threshold(compiler) == int(value)
    assert compiler.warnings == []


def test_an_unset_value_is_the_defaults_and_says_nothing():
    """0 is "copy the whole packet", 1 is "send every message".

    Both are what the print rules treat as "do not write the option",
    so an unset setting has to answer with them.
    """
    compiler = _Compiler()
    assert get_log_copy_range(compiler) == 0
    assert get_log_queue_threshold(compiler) == 1
    assert compiler.warnings == []


def test_the_message_says_what_nftables_would_read_instead():
    compiler = _Compiler(ulog_qthreshold='70000')
    get_log_queue_threshold(compiler)
    assert '4464' in compiler.warnings[0]
