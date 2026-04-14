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

"""Regression tests for Service.is_any() and TCPService shadowing.

Guards against a past bug where TCPService objects that inspected
TCP flags (xmas scan, illegal flag combinations, etc.) were treated
as the "any TCP" service by is_any(), causing DetectShadowing to
report every rule below them as shadowed.  See issue #73.
"""

import uuid

from firewallfabrik.compiler.processors._generic import _srv_contains
from firewallfabrik.core.objects import (
    IPService,
    TCPService,
    UDPService,
)


def _make_tcp(
    src_start=0,
    src_end=0,
    dst_start=0,
    dst_end=0,
    tcp_flags=None,
    tcp_flags_masks=None,
    data=None,
    name='test',
):
    svc = TCPService()
    svc.id = uuid.uuid4()
    svc.name = name
    svc.src_range_start = src_start
    svc.src_range_end = src_end
    svc.dst_range_start = dst_start
    svc.dst_range_end = dst_end
    svc.tcp_flags = tcp_flags
    svc.tcp_flags_masks = tcp_flags_masks
    svc.data = data
    return svc


def _make_udp(dst_start=0, dst_end=0, name='udp'):
    svc = UDPService()
    svc.id = uuid.uuid4()
    svc.name = name
    svc.src_range_start = 0
    svc.src_range_end = 0
    svc.dst_range_start = dst_start
    svc.dst_range_end = dst_end
    return svc


def _make_ip(proto_num, name='ip'):
    svc = IPService()
    svc.id = uuid.uuid4()
    svc.name = name
    svc.named_protocols = {'protocol_num': str(proto_num)}
    return svc


class TestServiceIsAny:
    """Unit tests for Service.is_any()."""

    def test_tcp_without_ports_or_flags_is_any(self):
        assert _make_tcp().is_any() is True

    def test_tcp_with_dst_port_is_not_any(self):
        assert _make_tcp(dst_start=80, dst_end=80).is_any() is False

    def test_tcp_with_src_port_is_not_any(self):
        assert _make_tcp(src_start=1024, src_end=65535).is_any() is False

    def test_tcp_xmas_scan_with_flag_masks_is_not_any(self):
        """Xmas scan: URG,PSH,FIN set, all six bits masked — not 'any'."""
        svc = _make_tcp(
            name='xmas scan',
            tcp_flags={
                'urg': True,
                'ack': False,
                'psh': True,
                'rst': False,
                'syn': False,
                'fin': True,
            },
            tcp_flags_masks={
                'urg': True,
                'ack': True,
                'psh': True,
                'rst': True,
                'syn': True,
                'fin': True,
            },
        )
        assert svc.is_any() is False

    def test_tcp_with_all_false_flags_is_any(self):
        """fwbuilder imports write all-false dicts for services without
        actual flag inspection — those must still be considered 'any'."""
        svc = _make_tcp(
            name='All TCP',
            tcp_flags=dict.fromkeys(('urg', 'ack', 'psh', 'rst', 'syn', 'fin'), False),
            tcp_flags_masks=dict.fromkeys(
                ('urg', 'ack', 'psh', 'rst', 'syn', 'fin'), False
            ),
        )
        assert svc.is_any() is True

    def test_tcp_established_is_not_any(self):
        """'All TCP established' sets data.established=true; not 'any'."""
        svc = _make_tcp(
            name='All TCP established',
            data={'established': True},
            tcp_flags=dict.fromkeys(('urg', 'ack', 'psh', 'rst', 'syn', 'fin'), False),
            tcp_flags_masks=dict.fromkeys(
                ('urg', 'ack', 'psh', 'rst', 'syn', 'fin'), False
            ),
        )
        assert svc.is_any() is False

    def test_udp_without_ports_is_any(self):
        assert _make_udp().is_any() is True

    def test_udp_with_dst_port_is_not_any(self):
        assert _make_udp(dst_start=53, dst_end=53).is_any() is False


class TestSrvContainsRegression73:
    """End-to-end regression tests for DetectShadowing logic on TCP flags.

    Before the fix, TCPService objects with specific flag masks were
    is_any()==True and therefore passed as the "s1_any → return True"
    short-circuit, making them appear to shadow every service below
    in the rule set (issue #73).
    """

    def _xmas_scan(self):
        return _make_tcp(
            name='xmas scan',
            tcp_flags={'urg': True, 'psh': True, 'fin': True},
            tcp_flags_masks=dict.fromkeys(
                ('urg', 'ack', 'psh', 'rst', 'syn', 'fin'), True
            ),
        )

    def test_xmas_scan_does_not_contain_unrelated_udp(self):
        assert _srv_contains(self._xmas_scan(), _make_udp(dst_start=53)) is False

    def test_xmas_scan_does_not_contain_unrelated_tcp(self):
        http = _make_tcp(name='http', dst_start=80, dst_end=80)
        assert _srv_contains(self._xmas_scan(), http) is False

    def test_xmas_scan_does_not_contain_ip_any(self):
        assert _srv_contains(self._xmas_scan(), _make_ip(0, name='Any')) is False

    def test_genuine_any_tcp_still_contains_specific_tcp(self):
        """Sanity check: the fix must not kill legitimate shadowing."""
        any_tcp = _make_tcp(name='All TCP')
        http = _make_tcp(name='http', dst_start=80, dst_end=80)
        assert _srv_contains(any_tcp, http) is True
