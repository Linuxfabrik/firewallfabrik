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

"""Values a rate limit may carry into an iptables command.

Everything here was asked of the real binary in a private network
namespace first, so the numbers are what iptables answers, not what the
source reads like:

    iptables -A INPUT -m hashlimit --hashlimit 100000000/second \\
        --hashlimit-name y            -> Rate too fast
    iptables -A INPUT -m hashlimit --hashlimit 10/second \\
        --hashlimit-name y --hashlimit-burst 2000000
                                      -> out of range (1-1000000)
    iptables -A INPUT -m hashlimit --hashlimit 10/second \\
        --hashlimit-name "a/b"        -> RULE_APPEND failed (Invalid argument)
    ip6tables -A INPUT -m connlimit --connlimit-above 2 \\
        --connlimit-mask 129          -> neither a valid network mask nor
                                         valid CIDR (0-128)

The IPv4 half of the last one is the reason it is checked rather than
passed on: iptables does not refuse `--connlimit-mask 64`, it reads the
value as the dotted mask 0.0.0.64 and groups connections by four bits of
the last octet.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.core.objects import PolicyAction
from firewallfabrik.platforms.iptables._print_rule import PrintRule


class _Compiler:
    """The bit of PolicyCompiler_ipt the printer reaches for."""

    def __init__(self, ipv6=False):
        self.ipv6_policy = ipv6
        self.muted_now = False
        self.hashlimit_tables = {}
        self.errors = []
        self.warnings = []

    def error(self, rule, message):
        self.errors.append(message)

    def warning(self, rule, message):
        self.warnings.append(message)


def _printer(ipv6=False, version='1.8'):
    printer = PrintRule(name='PrintRule')
    printer.compiler = _Compiler(ipv6=ipv6)
    printer.version = version
    return printer


def _rule(**options):
    return CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=1,
        label='',
        comment='',
        options=options,
        negations={},
        action=PolicyAction.Accept,
    )


@pytest.mark.parametrize(
    ('options', 'wanted'),
    [
        # Faster than the scale the match stores its rate in.
        ({'hashlimit_value': 100000000}, 'faster than'),
        # Wider than the burst any revision of the match takes.
        ({'hashlimit_value': 10, 'hashlimit_burst': 2000000}, 'out of range'),
        # A name the kernel cannot make a file under /proc out of, and one
        # the shell would read as an instruction.
        ({'hashlimit_value': 10, 'hashlimit_name': 'a/b'}, 'not part of a name'),
        ({'hashlimit_value': 10, 'hashlimit_name': 'a b'}, 'not part of a name'),
        ({'hashlimit_value': 10, 'hashlimit_name': '$(id)'}, 'not part of a name'),
    ],
)
def test_a_rate_limit_iptables_refuses_leaves_the_rule_out(options, wanted):
    printer = _printer()
    assert printer._print_hashlimit(_rule(**options)) is None
    assert any(wanted in message for message in printer.compiler.errors)


def test_a_rate_limit_within_range_is_printed():
    printer = _printer()
    out = printer._print_hashlimit(
        _rule(hashlimit_value=10, hashlimit_burst=5, hashlimit_name='ok')
    )
    assert '-m hashlimit --hashlimit 10 --hashlimit-burst 5' in out
    assert printer.compiler.errors == []


@pytest.mark.parametrize(
    ('ipv6', 'masklen', 'refused'),
    [
        (False, 32, False),
        (False, 33, True),
        (False, 64, True),
        (True, 64, False),
        (True, 128, False),
        (True, 129, True),
    ],
)
def test_a_connection_limit_groups_by_at_most_the_address_width(ipv6, masklen, refused):
    printer = _printer(ipv6=ipv6)
    out = printer._print_connlimit(_rule(connlimit_value=2, connlimit_masklen=masklen))
    if refused:
        assert out is None
        assert any('groups by at most' in m for m in printer.compiler.errors)
    else:
        assert f'--connlimit-mask {masklen}' in out
        assert printer.compiler.errors == []


@pytest.mark.parametrize(
    ('value', 'valid'),
    [
        ('1:11', True),
        ('0:0', True),
        ('ffff:ffff', True),
        ('1', False),
        ('1:2:3', False),
        ('', False),
        ('root', False),
    ],
)
def test_a_traffic_class_is_two_hexadecimal_numbers(value, valid):
    """iptables reads the class with sscanf("%x:%x").

    Anything else is `Bad class value`, which stops the activation script -
    verified against iptables 1.8.11 with `--set-class 1`.  nftables is
    looser and takes a bare number, but that is a different handle than
    the same policy would get on iptables, so both report it.
    """
    from firewallfabrik.platforms.linux._netfilter import is_valid_traffic_class

    assert is_valid_traffic_class(value) is valid


@pytest.mark.parametrize(
    ('value', 'valid'),
    [
        ('192.0.2.1', True),
        ('192.0.2.0/24', True),
        ('2001:db8::1', True),
        ('mgmt.example.com', True),
        # The value is spliced into a shell command and into an nftables
        # rule at the moment the block action has set every chain to drop.
        ('192.0.2.1; reboot', False),
        ('192.0.2.1 -j ACCEPT', False),
        ('$(id)', False),
        ('"', False),
        ('', False),
    ],
)
def test_the_backup_ssh_address_holds_nothing_but_an_address(value, valid):
    from firewallfabrik.platforms.linux._netfilter import is_valid_mgmt_address

    assert is_valid_mgmt_address(value) is valid


@pytest.mark.parametrize(
    ('value', 'valid'),
    [
        ('htable_rule_3', True),
        ('per-source.http', True),
        # The name goes unquoted into a command the activation script runs
        # as root, so everything the shell reads as syntax is refused.
        ('$(id)', False),
        ('`reboot`', False),
        ('a;reboot', False),
        ('a|sh', False),
        ('a&b', False),
        ("a'b", False),
        ('a table', False),
        # A slash would make the kernel refuse the rule: the name becomes a
        # file under /proc/net/ipt_hashlimit.
        ('a/b', False),
        ('', False),
    ],
)
def test_the_rate_limit_table_name_holds_nothing_but_a_name(value, valid):
    from firewallfabrik.platforms.iptables._print_rule import _HASHLIMIT_NAME_RE

    assert bool(_HASHLIMIT_NAME_RE.fullmatch(value)) is valid


@pytest.mark.parametrize(
    ('version', 'options', 'refused'),
    [
        # Revision 2 raised both ceilings by a hundred and first shipped in
        # iptables 1.6.1 (XT_HASHLIMIT_SCALE_v2, XT_HASHLIMIT_BURST_MAX).
        ('1.8.11', {'hashlimit_value': 500000}, False),
        ('1.6.1', {'hashlimit_value': 500000}, False),
        ('1.6.0', {'hashlimit_value': 500000}, True),
        ('1.4.21', {'hashlimit_value': 500000}, True),
        ('1.8.11', {'hashlimit_value': 10, 'hashlimit_burst': 500000}, False),
        ('1.6.0', {'hashlimit_value': 10, 'hashlimit_burst': 500000}, True),
        # Both releases take what revision 1 takes.
        ('1.6.0', {'hashlimit_value': 10000}, False),
        ('1.6.0', {'hashlimit_value': 10, 'hashlimit_burst': 10000}, False),
    ],
)
def test_the_rate_limit_ceilings_follow_the_pinned_release(version, options, refused):
    printer = _printer(version=version)
    assert (printer._print_hashlimit(_rule(**options)) is None) is refused


@pytest.mark.parametrize(
    ('suffix', 'wanted'),
    [
        # iptables takes any prefix of a unit name, nftables only the full
        # word, so the compiler settles on the full word for both.
        ('/second', '--hashlimit 10/second'),
        ('/sec', '--hashlimit 10/second'),
        ('/m', '--hashlimit 10/minute'),
        ('/HOUR', '--hashlimit 10/hour'),
        ('', '--hashlimit 10 '),
    ],
)
def test_a_rate_unit_is_written_out_in_full(suffix, wanted):
    printer = _printer()
    out = printer._print_hashlimit(
        _rule(hashlimit_value=10, hashlimit_suffix=suffix, hashlimit_name='ok')
    )
    assert wanted in out


def test_a_rate_unit_netfilter_does_not_know_leaves_the_rule_out():
    printer = _printer()
    rule = _rule(hashlimit_value=10, hashlimit_suffix='/fortnight', hashlimit_name='ok')
    assert printer._print_hashlimit(rule) is None
    assert any('not a unit' in message for message in printer.compiler.errors)


def test_a_short_rate_unit_is_measured_against_the_right_ceiling():
    # 500000/minute is below the revision-2 ceiling of a million per minute.
    # Reading "/min" as an unknown unit would compare it against the
    # per-second ceiling and refuse it.
    printer = _printer()
    out = printer._print_hashlimit(
        _rule(hashlimit_value=500000, hashlimit_suffix='/min', hashlimit_name='ok')
    )
    assert out is not None
    assert '--hashlimit 500000/minute' in out


@pytest.mark.parametrize(
    ('stored', 'wanted'),
    [
        # The two names the two tools spell differently: log_names[] in
        # libxtables/xtoptions.c holds "error" and "warning" and compares
        # with strcmp, nftables' level_type holds "err" and "warn".
        ('err', 'error'),
        ('warn', 'warning'),
        ('error', 'error'),
        ('warning', 'warning'),
        # Everything else is spelled the same way on both.
        ('info', 'info'),
        ('panic', 'panic'),
        ('debug', 'debug'),
    ],
)
def test_a_log_level_is_spelled_the_way_iptables_spells_it(stored, wanted):
    from firewallfabrik.platforms.iptables._print_rule import iptables_log_level

    assert iptables_log_level(stored) == wanted


@pytest.mark.parametrize(
    ('version', 'wanted'),
    [
        # 0f16c725 taught the parser the leading "!" and e0390bee made the
        # intrapositional one an error, both first in v1.4.3, so no release
        # accepts both spellings.  connlimit reaches back to 1.2.9, which
        # puts several releases below the cut-off within reach.
        ('1.4.2', '-m connlimit --connlimit-above ! 10'),
        ('1.4.3', '-m connlimit ! --connlimit-above 10'),
        ('1.8', '-m connlimit ! --connlimit-above 10'),
    ],
)
def test_a_negated_connection_limit_uses_the_spelling_of_its_release(version, wanted):
    """The block wrote a fixed leading "!", which 1.4.2 refuses outright."""
    printer = _printer(version=version)
    out = printer._print_connlimit(
        _rule(connlimit_value=10, connlimit_above_not=True),
    )
    assert out is not None
    assert out.strip() == wanted


def test_a_connection_limit_that_is_not_negated_is_written_plainly():
    printer = _printer(version='1.4.2')
    out = printer._print_connlimit(_rule(connlimit_value=10))
    assert out is not None
    assert out.strip() == '-m connlimit --connlimit-above 10'
