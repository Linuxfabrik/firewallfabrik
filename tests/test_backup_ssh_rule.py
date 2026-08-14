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

"""The backup ssh rule belongs to the ruleset, not only to block and stop.

``mgmt_ssh`` promises permanent ssh access from the management workstation,
and fwbuilder writes the two rules into the automatic rules of the ruleset
itself (``PolicyCompiler_ipt::PrintRule::_printBackupSSHAccessRules``).
Having them only in the ``block`` and ``stop`` actions means the activation
that installs a default-drop policy cuts the session that is activating it.

The rule belongs to the pass whose family the address has: iptables answers
an IPv6 address with "host/network not found" and nftables refuses an
``ip6`` match inside an ``ip`` table, both at the moment every chain has
just been set to drop.
"""

from firewallfabrik.platforms.iptables._policy_compiler import PolicyCompiler_ipt
from firewallfabrik.platforms.nftables._os_configurator import OSConfigurator_nft

_V4 = '192.0.2.9'
_V6 = '2001:db8::9'


class _FakeFW:
    version = ''

    def __init__(self, options):
        self._options = options

    def get_option(self, key):
        return self._options.get(key)

    @property
    def interfaces(self):
        return []


def _options(**overrides):
    options = {
        'accept_established': True,
        'accept_new_tcp_with_no_syn': True,
        'add_rules_for_ipv6_neighbor_discovery': False,
        'bridging_fw': False,
        'drop_invalid': False,
        'linux24_ip_forward': '1',
        'linux24_ipv6_forward': '1',
        'log_invalid': False,
        'mgmt_addr': _V4,
        'mgmt_ssh': True,
        'use_NFLOG': False,
        'use_iptables_restore': False,
    }
    options.update(overrides)
    return options


def _ipt_automatic_rules(ipv6: bool, **overrides) -> str:
    compiler = PolicyCompiler_ipt.__new__(PolicyCompiler_ipt)
    compiler.fw = _FakeFW(_options(**overrides))
    compiler.single_rule_compile_mode = False
    compiler.version = '1.8'
    compiler.ipv6_policy = ipv6
    compiler.chain_prefix = ''
    compiler._warnings = []
    compiler.warning = compiler._warnings.append
    return compiler.print_automatic_rules()


def _nft_automatic_rules(chain: str, have_ipv6: bool, **overrides) -> str:
    oc = OSConfigurator_nft.__new__(OSConfigurator_nft)
    oc.fw = _FakeFW(_options(**overrides))
    return oc.generate_automatic_rules(chain, have_ipv6)


def test_ipt_ipv4_address_lands_in_the_ipv4_pass():
    out = _ipt_automatic_rules(ipv6=False)
    assert '# backup ssh access' in out
    assert f'-A INPUT  -p tcp -m tcp  -s {_V4}  --dport 22' in out
    assert f'-A OUTPUT  -p tcp -m tcp  -d {_V4}  --sport 22' in out


def test_ipt_ipv4_address_is_left_out_of_the_ipv6_pass():
    # ip6tables answers an IPv4 address with "host/network not found" and
    # stops the activation script there.
    assert '# backup ssh access' not in _ipt_automatic_rules(ipv6=True)


def test_ipt_ipv6_address_lands_in_the_ipv6_pass_only():
    assert '# backup ssh access' in _ipt_automatic_rules(ipv6=True, mgmt_addr=_V6)
    assert '# backup ssh access' not in _ipt_automatic_rules(ipv6=False, mgmt_addr=_V6)


def test_ipt_no_rule_without_the_option():
    assert '# backup ssh access' not in _ipt_automatic_rules(ipv6=False, mgmt_ssh=False)
    assert '# backup ssh access' not in _ipt_automatic_rules(ipv6=False, mgmt_addr='')


def test_ipt_no_rule_for_an_address_the_script_cannot_carry():
    # The value is spliced into a shell command; the driver reports it.
    out = _ipt_automatic_rules(ipv6=False, mgmt_addr='192.0.2.9; reboot')
    assert '# backup ssh access' not in out


def test_nft_input_and_output_carry_the_rule():
    assert (
        f'tcp dport 22 ip saddr {_V4} ct state new,established counter accept'
        in _nft_automatic_rules('input', have_ipv6=False)
    )
    assert (
        f'tcp sport 22 ip daddr {_V4} ct state established,related counter accept'
        in _nft_automatic_rules('output', have_ipv6=False)
    )


def test_nft_forward_does_not():
    # A packet between the management station and the firewall never
    # crosses the forward chain.
    assert 'dport 22' not in _nft_automatic_rules('forward', have_ipv6=False)


def test_nft_names_the_family_of_the_address():
    out = _nft_automatic_rules('input', have_ipv6=True, mgmt_addr=_V6)
    assert f'ip6 saddr {_V6}' in out


def test_nft_leaves_an_ipv6_address_out_of_an_ip_table():
    # Without an IPv6 rule set the filter table is `ip`, which cannot hold
    # an `ip6` match at all: nft refuses the whole ruleset over it.
    assert 'dport 22' not in _nft_automatic_rules(
        'input', have_ipv6=False, mgmt_addr=_V6
    )


def test_nft_no_rule_without_the_option():
    assert 'dport 22' not in _nft_automatic_rules(
        'input', have_ipv6=False, mgmt_ssh=False
    )
    assert 'dport 22' not in _nft_automatic_rules(
        'input', have_ipv6=False, mgmt_addr=''
    )


def test_nft_rule_comes_before_every_drop():
    # The iptables configlet puts it "as early as possible so that the ssh
    # session opened from the management station won't break".
    out = _nft_automatic_rules(
        'input', have_ipv6=False, drop_invalid=True, accept_new_tcp_with_no_syn=False
    )
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    ssh = next(i for i, line in enumerate(lines) if 'dport 22' in line)
    drops = [i for i, line in enumerate(lines) if line.endswith('drop')]
    assert drops
    assert ssh < min(drops)
