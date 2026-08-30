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

"""A Custom Service whose iptables code is a connection-state match.

Firewall Builder never had an nftables compiler, so every Custom Service a
data file brings along says iptables and nothing else.  The one that
matters is the "accept established and related" match a stateful policy is
built out of: leaving its rule out turns the whole policy into one that
drops every answer.

The mapping is netfilter's own (`state_xlate_print` and
`_conntrack3_mt_xlate`, extensions/libxt_conntrack.c) and it is checked
here against `iptables-translate` where that tool is installed.
"""

import shutil
import subprocess  # nosec B404

import pytest

from firewallfabrik.platforms.linux._netfilter import (
    custom_service_code,
    custom_service_matches_state,
    custom_service_nftables_code,
)

TRANSLATED = {
    # The two spellings of the same match, both of which the corpus carries.
    '-m state --state ESTABLISHED,RELATED': 'ct state related,established',
    '-m conntrack --ctstate ESTABLISHED,RELATED': 'ct state related,established',
    '-m state --state INVALID': 'ct state invalid',
    '-m conntrack --ctstate NEW': 'ct state new',
    '-m conntrack --ctstate UNTRACKED': 'ct state untracked',
    # `strncasecmp(token, name, strlen(token))` reads a prefix as the name.
    '-m state --state EST': 'ct state established',
    '-m state --state established,related': 'ct state related,established',
    # The output order is netfilter's, not the order they were written in.
    '-m conntrack --ctstate NEW,ESTABLISHED,RELATED,INVALID,UNTRACKED': (
        'ct state invalid,new,related,established,untracked'
    ),
    # Whitespace around the code is what a text field collects.
    '  -m conntrack   --ctstate  ESTABLISHED  ': 'ct state established',
    '-m conntrack ! --ctstate NEW': 'ct state != new',
}

NOT_TRANSLATED = (
    # nftables has no equivalent for any of these.
    '-m recent --update --seconds 300 --hitcount 3',
    '-m string --string test_pattern',
    '-m psd --psd-weight-threshold 5',
    '-m irc',
    # SNAT and DNAT are `ct status`, and netfilter's own translator drops
    # the second of the two and every state named beside them.
    '-m conntrack --ctstate SNAT',
    '-m conntrack --ctstate DNAT,SNAT',
    '-m conntrack --ctstate NEW,SNAT',
    # A state match beside another condition is not a state match.
    '-p tcp -m state --state ESTABLISHED --tcp-flags SYN,ACK,RST,URG ACK',
    '-m state --state NEW -j LOG',
    # The module and its option have to belong together.
    '-m state --ctstate NEW',
    '-m conntrack --state NEW',
    # A name neither tool knows, and an empty element in the list.
    '-m state --state XYZ',
    '-m conntrack --ctstate ESTABLISHED,',
    '-m conntrack --ctstate ,ESTABLISHED',
    # `--state` takes no spaces in its list; `state_parse_states` says so.
    '-m state --state ESTABLISHED, RELATED',
    '',
)


@pytest.mark.parametrize(('code', 'expected'), sorted(TRANSLATED.items()))
def test_a_state_match_reaches_nftables(code, expected):
    assert custom_service_nftables_code(code) == expected


@pytest.mark.parametrize('code', NOT_TRANSLATED)
def test_everything_else_is_left_to_the_caller_to_report(code):
    assert custom_service_nftables_code(code) is None


def test_the_firewalls_own_nftables_code_wins():
    """A service that says nftables is never second-guessed."""
    srv = _service(iptables='-m state --state NEW', nftables='ct state new,related')
    assert custom_service_code(srv, 'nftables') == 'ct state new,related'


def test_a_service_with_no_iptables_code_stays_unconfigured():
    srv = _service(pf='keep state')
    assert custom_service_code(srv, 'nftables') == ''
    assert custom_service_code(srv, 'iptables') == ''


def test_the_iptables_side_is_not_touched():
    """The fallback is for nftables alone: iptables has the real code."""
    srv = _service(iptables='-m state --state ESTABLISHED,RELATED')
    assert (
        custom_service_code(srv, 'iptables') == '-m state --state ESTABLISHED,RELATED'
    )
    assert custom_service_code(srv, 'pf') == ''


def test_the_translation_is_recognised_as_matching_the_state():
    """Or the compiler would put its own `ct state new` beside it.

    `SpecialCasesWithCustomServices` marks such a rule stateless, and it
    has to give one and the same object the same answer on both platforms.
    """
    srv = _service(iptables='-m conntrack --ctstate ESTABLISHED,RELATED')
    assert custom_service_matches_state(custom_service_code(srv, 'nftables'))
    assert custom_service_matches_state(custom_service_code(srv, 'iptables'))


@pytest.mark.parametrize(('code', 'expected'), sorted(TRANSLATED.items()))
def test_against_iptables_translate(code, expected):
    """The tool itself, where it is installed."""
    if shutil.which('iptables-translate') is None:
        pytest.skip('iptables-translate not installed')
    argv = ['iptables-translate', '-A', 'FORWARD', *code.split(), '-j', 'ACCEPT']
    result = subprocess.run(  # nosec B603 B607
        argv, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        pytest.skip(f'iptables-translate refuses this release: {result.stderr.strip()}')
    # The tool spells a negation `! new` where nftables prints `!= new`
    # back; both parse, and fwf writes the one the rest of its output uses.
    printed = result.stdout.replace('ct state ! ', 'ct state != ')
    assert expected in printed


class _Service:
    def __init__(self, codes):
        self.codes = codes
        self.name = 'test'


def _service(**codes):
    return _Service(codes)
