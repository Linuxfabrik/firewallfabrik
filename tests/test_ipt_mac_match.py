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

"""Where the negation of a MAC match goes on the iptables command line.

`--mac-source` carries XTOPT_INVERT (netfilter extensions/libxt_mac.c), so
the `!` belongs between `-m mac` and the option.  A `!` in front of the
`-m` is a parse error of its own ("unexpected ! flag before --match",
iptables xshared.c), and `-m mac!` names a match module that does not
exist - both stop the activation script with the built-in policies
already set to DROP.

The forms are asserted as strings rather than through a fixture because
no `.fwb` or `.fwf` in the corpus negates a MAC, and the two spellings
depend on the iptables release the firewall pins.
"""

import re

import pytest

from firewallfabrik.compiler._combined_address import CombinedAddress
from firewallfabrik.compiler._rule_processor import NATRuleProcessor
from firewallfabrik.platforms.iptables._nat_compiler import VerifyRuleWithMAC
from firewallfabrik.platforms.iptables._nat_print_rule import NATPrintRule
from firewallfabrik.platforms.iptables._print_rule import PrintRule

MAC = 'aa:bb:cc:dd:ee:ff'

# What iptables accepts, per release.  1.4.3 taught the leading "!" and
# made the intrapositioned one an error, so exactly one of the two is
# right for a given target.
EXTRAPOSITIONED = f'-m mac ! --mac-source {MAC}'
INTRAPOSITIONED = f'-m mac --mac-source ! {MAC}'


class _Compiler:
    """Just enough compiler for the two printers' negation helper."""

    def __init__(self) -> None:
        self.messages: list[str] = []

    def warning(self, _rule, msg: str) -> None:
        self.messages.append(msg)

    def error(self, _rule, msg: str) -> None:
        self.messages.append(msg)

    def abort(self, _rule, msg: str) -> None:
        self.messages.append(msg)


class _Rule:
    """A rule element carrying a single negated object."""

    def __init__(self, slot: str, negated: bool) -> None:
        setattr(self, f'{slot}_single_object_negation', negated)


class _Phys:
    name = 'mac-only-host'

    def get_address(self) -> str:
        return MAC


def _policy_match(version: str, negated: bool) -> str:
    printer = PrintRule('print rule')
    printer.compiler = _Compiler()
    printer.version = version
    return printer._print_mac_source(_Phys(), _Rule('src', negated))


def _nat_negation(version: str, negated: bool) -> str:
    printer = NATPrintRule('print nat rule')
    printer.compiler = _Compiler()
    printer.version = version
    neg = printer._print_single_option_with_negation(
        '--mac-source', _Rule('osrc', negated), 'osrc', MAC
    )
    return f'-m mac {neg}'


def _squeeze(text: str) -> str:
    return re.sub(r'\s+', ' ', text).strip()


@pytest.mark.parametrize('render', [_policy_match, _nat_negation])
@pytest.mark.parametrize(
    ('version', 'expected'),
    [
        ('1.8.11', EXTRAPOSITIONED),
        ('1.4.3', EXTRAPOSITIONED),
        ('1.4.0', INTRAPOSITIONED),
        ('1.3.0', INTRAPOSITIONED),
    ],
)
def test_negated_mac_match(render, version, expected):
    assert _squeeze(render(version, True)) == expected


@pytest.mark.parametrize('render', [_policy_match, _nat_negation])
@pytest.mark.parametrize('version', ['1.8.11', '1.3.0'])
def test_plain_mac_match(render, version):
    assert _squeeze(render(version, False)) == f'-m mac --mac-source {MAC}'


class _Address:
    """An address object as the MAC guard sees it."""

    def __init__(self, name: str, address: str) -> None:
        self.name = name
        self._address = address

    def get_address(self) -> str:
        return self._address


class _NATRule:
    type = 'NATRule'

    def __init__(self, chain: str, osrc: list) -> None:
        self.ipt_chain = chain
        self.osrc = osrc


class _Feeder(NATRuleProcessor):
    def __init__(self, rule) -> None:
        super().__init__(name='feeder')
        self.tmp_queue.append(rule)

    def process_next(self) -> bool:
        return False


def _verify_mac(chain: str, osrc: list):
    """Run VerifyRuleWithMAC over a rule and return (rule or None, messages)."""
    compiler = _Compiler()
    rule = _NATRule(chain, osrc)
    proc = VerifyRuleWithMAC('verify MAC')
    proc.compiler = compiler
    proc.set_data_source(_Feeder(rule))
    proc.process_next()
    out = proc.tmp_queue[0] if proc.tmp_queue else None
    return out, compiler.messages


def test_combined_address_keeps_its_ip_half_in_postrouting():
    """The chain cannot match a MAC, but it can match the address.

    fwbuilder clears the MAC and keeps the address
    (NATCompiler_ipt.cpp:2288); leaving the object whole produced a
    `-m mac` in POSTROUTING, which the kernel refuses with -EINVAL
    because xt_mac registers for PREROUTING, INPUT and FORWARD only.
    """
    combined = CombinedAddress(_Address('host-with-mac/addr', '192.0.2.5'), _Phys())
    out, messages = _verify_mac('POSTROUTING', [combined])
    assert out is not None
    assert [obj.get_address() for obj in out.osrc] == ['192.0.2.5']
    assert not any(getattr(obj, 'has_phys_address', bool)() for obj in out.osrc)
    assert messages and 'can not match MAC address' in messages[0]


def test_combined_address_with_no_ip_leaves_the_rule_without_a_source():
    combined = CombinedAddress(_Address('mac-only/addr', ''), _Phys())
    out, messages = _verify_mac('POSTROUTING', [combined])
    assert out is None
    assert messages and "it becomes 'Any'" in messages[0]


def test_prerouting_keeps_the_mac():
    combined = CombinedAddress(_Address('host-with-mac/addr', '192.0.2.5'), _Phys())
    out, messages = _verify_mac('PREROUTING', [combined])
    assert out is not None
    assert out.osrc == [combined]
    assert not messages
