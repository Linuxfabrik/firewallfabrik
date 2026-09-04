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

"""A Custom Service whose iptables code nftables has a spelling for.

Firewall Builder never had an nftables compiler, so every Custom Service a
data file brings along says iptables and nothing else.  The one that
matters most is the "accept established and related" match a stateful
policy is built out of: leaving its rule out turns the whole policy into
one that drops every answer.

The code is read as a sequence of matches and every one of them has to
translate, or the whole code is refused.  The mapping is netfilter's own
(`state_xlate_print` and `_conntrack3_mt_xlate` in
extensions/libxt_conntrack.c, `tcp_xlate` in libxt_tcp.c, `owner_xlate`
in libxt_owner.c, `rt_xlate` in libip6t_rt.c) and it is checked here
against `iptables-translate` / `ip6tables-translate` where those tools
are installed.
"""

import shutil
import socket
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
    # `!` and not `!=`.  On a bitmask the two are different operators:
    # `!` compiles to `state & <bits> == 0`, which is what
    # `! --ctstate NEW,RELATED` says, and `!=` to `state != <bits>`,
    # which a packet carrying exactly one state bit always satisfies -
    # so the second spelling matches every packet there is
    # (netfilter nftables src/netlink_linearize.c, netlink_gen_flagcmp).
    '-m conntrack ! --ctstate NEW': 'ct state ! new',
    '-m conntrack ! --ctstate NEW,RELATED': 'ct state ! new,related',
    '-m state ! --state ESTABLISHED,RELATED': 'ct state ! related,established',
    # A TCP flag inspection, alone and beside a state match.  `-m tcp`
    # carries no match of its own; its options do.
    '-m tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW': (
        'tcp flags syn,ack / syn,ack ct state new'
    ),
    '-p tcp -m state --state ESTABLISHED --tcp-flags SYN,ACK,RST,URG ACK': (
        'ct state established tcp flags ack / syn,rst,ack,urg'
    ),
    # The user a `-m owner` match names is what a User Service object
    # already compiles to on both platforms.
    '-m owner --uid-owner 1000': 'meta skuid 1000',
    '-m owner ! --uid-owner 1000': 'meta skuid != 1000',
    '-m owner --gid-owner 0': 'meta skgid 0',
}

# Translated, but not the way `iptables-translate` writes it.  Each of
# these is the spelling fwf writes for the equivalent object of its own
# model, because one and the same condition must not read differently
# depending on which kind of object carries it.
TRANSLATED_OUR_WAY = {
    # The tool resolves the name against the *compiling* host's passwd
    # file; nftables resolves it on the host that loads the ruleset, which
    # is the firewall and the only one that can answer.
    '-m owner --uid-owner anonymous': 'meta skuid anonymous',
    # `meta l4proto` where the tool writes `ip protocol`: fwf's filter
    # table is `inet` for a dual-stack firewall, where `ip protocol` would
    # pin the rule to IPv4.
    '-p udp': 'meta l4proto udp',
    # The bitwise form `tcp_flags_match_nft` writes, which nft takes for
    # every mask - the tool's `value / mask` form is refused when the mask
    # names a single flag.
    '-m tcp --tcp-flags ALL NONE': (
        'tcp flags & (fin | syn | rst | psh | ack | urg) == 0x0'
    ),
    '-p tcp --syn': 'tcp flags syn / fin,syn,rst,ack',
    '-p tcp ! --syn': 'tcp flags & (fin | syn | rst | ack) != syn',
}

# The routing-header match, which exists as `libip6t_rt.c` alone.  Every
# line here is one of the eight in extensions/libip6t_rt.txlate.
TRANSLATED_V6 = {
    '-m rt --rt-type 0': 'rt type 0',
    '-m rt ! --rt-len 22': 'rt hdrlength != 22',
    '-m rt --rt-segsleft 26': 'rt seg-left 26',
    '-m rt --rt-type 0 --rt-len 22': 'rt type 0 rt hdrlength 22',
    '-m rt --rt-type 0 --rt-len 22 ! --rt-segsleft 26': (
        'rt type 0 rt seg-left != 26 rt hdrlength 22'
    ),
    '-m rt --rt-segsleft 13:42': 'rt seg-left 13-42',
    # The whole 32-bit range is no condition, which is `skip_segsleft_match`.
    '-m rt --rt-segsleft 0:4294967295': 'exthdr rt exists',
    '-m rt ! --rt-segsleft 0:4294967295': 'rt seg-left != 0-4294967295',
    # The module on its own says the same thing.
    '-m rt': 'exthdr rt exists',
}

NOT_TRANSLATED_V6 = (
    # `rt_xlate` answers 0 for the three RT0 options, so netfilter's own
    # translator declines them too.
    '-m rt --rt-0-res',
    '-m rt --rt-0-not-strict',
    '-m rt --rt-type 0 --rt-0-addrs ::1',
    # An option of a match that was never named.
    '--rt-type 0',
    # A range where the option takes a single number, and a value that is
    # no number or does not fit in the 32 bits the match stores.
    '-m rt --rt-len 1:2',
    '-m rt --rt-type zero',
    '-m rt --rt-type 4294967296',
    '-m rt --rt-type 0 --rt-type 2',
)

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
    # A verdict is not a match, and the typo in this one is in the corpus.
    '-m state --state NEW -j LOG',
    '-p tcp ! --syn -dport 5190 -m state --state NEW',
    # A flag that is not a flag, and a comparison outside its own mask.
    '-m tcp --tcp-flags SYN,XYZ SYN',
    '-m tcp --tcp-flags SYN ACK',
    # A user name that would reach the generated script as a shell word.
    '-m owner --uid-owner $(id -u)',
    # A protocol nftables would have to be guessed at.
    '-p 47',
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


@pytest.mark.parametrize(('code', 'expected'), sorted(TRANSLATED_OUR_WAY.items()))
def test_the_spelling_is_the_one_fwf_writes_elsewhere(code, expected):
    assert custom_service_nftables_code(code) == expected


@pytest.mark.parametrize('code', NOT_TRANSLATED)
def test_everything_else_is_left_to_the_caller_to_report(code):
    assert custom_service_nftables_code(code) is None


@pytest.mark.parametrize(('code', 'expected'), sorted(TRANSLATED_V6.items()))
def test_the_routing_header_match_reaches_nftables(code, expected):
    assert custom_service_nftables_code(code, ipv6_only=True) == expected


@pytest.mark.parametrize('code', NOT_TRANSLATED_V6)
def test_a_routing_header_match_it_cannot_read_is_reported(code):
    assert custom_service_nftables_code(code, ipv6_only=True) is None


@pytest.mark.parametrize('code', sorted(TRANSLATED_V6))
def test_the_routing_header_match_needs_a_service_that_says_ipv6(code):
    """`rt type` in an `ip` table is "cannot use exthdr with ip".

    nft refuses the whole ruleset over it, not the one rule, so a service
    that does not declare itself IPv6-only is reported instead - which is
    what happens to it on the iptables side too, where `libip6t_rt.c` is
    not a module `iptables` can load.
    """
    assert custom_service_nftables_code(code, ipv6_only=False) is None
    assert custom_service_code(_service(iptables=code), 'nftables') == ''
    assert (
        custom_service_code(_service(iptables=code, ipv6=True), 'nftables')
        == TRANSLATED_V6[code]
    )


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


def _translate(tool: str, code: str) -> str:
    """Return what *tool* makes of *code*, or skip when it cannot say.

    Two ways the tool declines, and both mean "this release cannot answer
    for this match", not "the compiler is wrong".  It exits non-zero for a
    match it does not know at all - and for one it knows but has no
    translator for, it exits **zero** and writes the rule without that
    match, which would otherwise read as the compiler inventing a
    condition.  The empty translation is what tells the second case apart.
    """
    if shutil.which(tool) is None:
        pytest.skip(f'{tool} not installed')

    def run(extra: list[str]) -> subprocess.CompletedProcess:
        argv = [tool, '-A', 'FORWARD', *extra, '-j', 'ACCEPT']
        return subprocess.run(  # nosec B603 B607
            argv, capture_output=True, text=True, check=False
        )

    result = run(code.split())
    if result.returncode != 0:
        pytest.skip(f'{tool} refuses this release: {result.stderr.strip()}')
    bare = run([])
    if bare.returncode == 0 and result.stdout == bare.stdout:
        pytest.skip(f'{tool} of this release has no translation for "{code}"')
    return result.stdout


@pytest.mark.parametrize(('code', 'expected'), sorted(TRANSLATED.items()))
def test_against_iptables_translate(code, expected):
    """The tool itself, where it is installed."""
    stdout = _translate('iptables-translate', code)
    # One spelling the tool writes short where nftables prints it back in
    # full: the socket user as `skuid` rather than `meta skuid`.  Both
    # parse and mean the same, and fwf writes the one the rest of its
    # output uses.  The negation is *not* normalised: `!` and `!=` are
    # different operators on a bitmask, so a difference there is a
    # finding and not a spelling.
    printed = stdout.replace('skuid ', 'meta skuid ')
    printed = printed.replace('skgid ', 'meta skgid ')
    assert expected in printed


class _Service:
    def __init__(self, codes, ipv6=False):
        self.codes = codes
        self.name = 'test'
        self.custom_address_family = socket.AF_INET6 if ipv6 else None


def _service(ipv6=False, **codes):
    return _Service(codes, ipv6=ipv6)


@pytest.mark.parametrize(('code', 'expected'), sorted(TRANSLATED_V6.items()))
def test_against_ip6tables_translate(code, expected):
    """The tool itself, where it is installed - `-m rt` is IPv6-only."""
    assert expected in _translate('ip6tables-translate', code)
