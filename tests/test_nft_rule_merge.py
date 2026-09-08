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

"""Putting the addresses of one rule element back into one nftables rule.

A chain decision hands a rule element out one address at a time, and
`optimize_chain_rules` collects the pieces back into one rule with an
anonymous set.  For a positive element that is cosmetic - one rule per
address is the same "any of these".  For a **negated** one it is the whole
meaning: "none of these" is a conjunction, and two rules each excluding
one address are an "or" that every packet satisfies, so a Deny built on
it blocks nothing and an Accept lets everything through
(`tools/compiler-audit/check-negations.py` is the oracle for that class).

The merge used to look at the next entry only, and a rule that logs
before it acts writes two lines: with "Log all rules" on, the log line of
the second address sat between the two action rules and the merge stopped
there, leaving exactly that "or" behind.  Found by compiling the
reference corpus with `--firewall-option bridging_fw=true
--firewall-option log_all=true`, which the corpus itself never reaches.
"""

from firewallfabrik.platforms.nftables._print_rule import optimize_chain_rules

LABEL = '        # \n        # Rule 0 (global)\n        # \n'


def _merge(entries):
    chain_rules = {'forward': list(entries)}
    optimize_chain_rules(chain_rules)
    return [line for entry in chain_rules['forward'] for line in entry.splitlines()]


def test_two_addresses_of_one_element_become_one_rule():
    lines = _merge(
        [
            LABEL + '        ip daddr != 10.1.0.0/24 counter accept\n',
            '        ip daddr != 10.2.0.0/24 counter accept\n',
        ]
    )

    assert lines == [
        '        # ',
        '        # Rule 0 (global)',
        '        # ',
        '        ip daddr != { 10.1.0.0/24, 10.2.0.0/24 } counter accept',
    ]


def test_a_log_line_between_them_does_not_stop_the_merge():
    """The shape "Log all rules" produces: one entry holds two rules."""
    lines = _merge(
        [
            LABEL
            + '        ip daddr != 10.1.0.0/24 counter log level info\n'
            + '        ip daddr != 10.1.0.0/24 counter accept\n',
            '        ip daddr != 10.2.0.0/24 counter log level info\n'
            + '        ip daddr != 10.2.0.0/24 counter accept\n',
        ]
    )

    assert lines[-2:] == [
        '        ip daddr != { 10.1.0.0/24, 10.2.0.0/24 } counter log level info',
        '        ip daddr != { 10.1.0.0/24, 10.2.0.0/24 } counter accept',
    ]


def test_a_warning_between_them_does_not_stop_the_merge():
    """A reported rule carries its message in front of its own line."""
    lines = _merge(
        [
            LABEL + '        ip saddr 10.1.0.0/24 counter accept\n',
            '        # fw:Policy:0: warning: something\n'
            '        ip saddr 10.2.0.0/24 counter accept\n',
        ]
    )

    assert '        ip saddr { 10.1.0.0/24, 10.2.0.0/24 } counter accept' in lines
    assert '        # fw:Policy:0: warning: something' in lines


def test_two_original_rules_are_never_merged():
    lines = _merge(
        [
            LABEL + '        ip saddr 10.1.0.0/24 counter accept\n',
            '        # \n        # Rule 1 (global)\n        # \n'
            '        ip saddr 10.2.0.0/24 counter accept\n',
        ]
    )

    assert '        ip saddr 10.1.0.0/24 counter accept' in lines
    assert '        ip saddr 10.2.0.0/24 counter accept' in lines


def test_the_same_address_twice_is_written_once():
    lines = _merge(
        [
            LABEL + '        ip saddr 10.1.0.0/24 counter accept\n',
            '        ip saddr 10.1.0.0/24 counter accept\n',
        ]
    )

    assert lines[-1] == '        ip saddr 10.1.0.0/24 counter accept'


def test_rules_that_differ_in_more_than_the_address_are_left_alone():
    lines = _merge(
        [
            LABEL + '        iifname "eth0" ip saddr 10.1.0.0/24 counter accept\n',
            '        iifname "eth1" ip saddr 10.2.0.0/24 counter accept\n',
        ]
    )

    assert '        iifname "eth0" ip saddr 10.1.0.0/24 counter accept' in lines
    assert '        iifname "eth1" ip saddr 10.2.0.0/24 counter accept' in lines


def test_a_rule_naming_a_named_set_is_not_folded_into_an_anonymous_one():
    """nftables rejects `{ @set, addr }`."""
    lines = _merge(
        [
            LABEL + '        ip saddr @i_eth0 counter accept\n',
            '        ip saddr 10.2.0.0/24 counter accept\n',
        ]
    )

    assert '        ip saddr @i_eth0 counter accept' in lines
    assert '        ip saddr 10.2.0.0/24 counter accept' in lines


def test_a_rate_limit_key_inside_braces_is_not_the_rule_address():
    """`meter x { ip saddr ... }` names the same field and is not a match."""
    meter = 'meter m { ip saddr timeout 1s limit rate 10/second }'
    lines = _merge(
        [
            LABEL + f'        ip daddr 10.1.0.0/24 {meter} counter accept\n',
            f'        ip daddr 10.2.0.0/24 {meter} counter accept\n',
        ]
    )

    assert (
        f'        ip daddr {{ 10.1.0.0/24, 10.2.0.0/24 }} {meter} counter accept'
        in lines
    )
