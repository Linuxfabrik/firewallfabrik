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

"""The automatic INVALID drop leaves loopback traffic to the policy.

firewalld accepts lo ahead of its INVALID drop (src/firewall/core/
nftables.py, build_default_rules).  FirewallFabrik exempts lo from the
drop instead, so a packet conntrack calls INVALID on lo reaches the
policy, where a stateless loopback rule accepts it.

The packet tests send a TCP RST to 127.0.0.1 with no connection behind
it.  conntrack has no state to move such a segment from (``sNO`` with
RST is ``sIV``, ``tcp_new`` refuses it, net/netfilter/
nf_conntrack_proto_tcp.c), so it is INVALID in the output and the input
hook.  A probe that counts INVALID packets ahead of the filter proves
that, and the same ruleset without the exemption drops the packet, so a
pass is not a probe that missed the code path.
"""

import re
import shlex
import subprocess  # nosec B404

import pytest

from firewallfabrik.platforms.iptables._policy_compiler import PolicyCompiler_ipt
from firewallfabrik.platforms.nftables._os_configurator import OSConfigurator_nft
from tests.tool_probe import (
    CAN_ASK_IPTABLES,
    CAN_ASK_NFT,
    SKIP_REASON,
    SKIP_REASON_IPTABLES,
)


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
        'drop_invalid': True,
        'linux24_ip_forward': '1',
        'linux24_ipv6_forward': '1',
        'log_invalid': False,
        'mgmt_ssh': False,
        'use_NFLOG': False,
        'use_iptables_restore': False,
    }
    options.update(overrides)
    return options


def _nft_rules(chain: str) -> str:
    oc = OSConfigurator_nft.__new__(OSConfigurator_nft)
    oc.fw = _FakeFW(_options())
    return oc.generate_automatic_rules(chain, have_ipv6=True)


def _ipt_rules() -> str:
    compiler = PolicyCompiler_ipt.__new__(PolicyCompiler_ipt)
    compiler.fw = _FakeFW(_options())
    compiler.single_rule_compile_mode = False
    compiler.version = '1.8'
    compiler.ipv6_policy = False
    compiler.chain_prefix = ''
    compiler._warnings = []
    compiler.warning = compiler._warnings.append
    return compiler.print_automatic_rules()


def _invalid_lines(text: str) -> list[str]:
    return [
        line.strip()
        for line in text.splitlines()
        if 'ct state invalid' in line or 'INVALID' in line
    ]


@pytest.mark.parametrize(
    ('chain', 'exemption'), [('input', 'iif != "lo" '), ('output', 'oif != "lo" ')]
)
def test_nft_exempts_loopback(chain, exemption):
    lines = _invalid_lines(_nft_rules(chain))
    assert lines
    assert all(line.startswith(exemption) for line in lines)


def test_nft_forward_chain_has_no_exemption():
    # A forwarded packet never has lo as its interface.
    lines = _invalid_lines(_nft_rules('forward'))
    assert lines
    assert not any('"lo"' in line for line in lines)


@pytest.mark.parametrize(
    ('chain', 'exemption'),
    [('INPUT', '! -i lo'), ('OUTPUT', '! -o lo'), ('FORWARD', None)],
)
def test_ipt_exempts_loopback(chain, exemption):
    lines = [line for line in _invalid_lines(_ipt_rules()) if f'-A {chain} ' in line]
    assert lines
    for line in lines:
        if exemption:
            assert exemption in line
        else:
            assert ' lo ' not in line


# Sends one TCP RST from 127.0.0.1 to 127.0.0.1:9 with no connection
# behind it.  The kernel adds the IP header; the TCP checksum is computed
# over the pseudo header so nothing but the missing connection is wrong.
# A drop in the output hook comes back to the sender as EPERM
# (net/netfilter/core.c, nf_hook_slow returns -EPERM for NF_DROP), which is
# the outcome the control case expects, so it is not an error here.
_SEND_RST = r"""
import socket, struct
def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff
tcp = struct.pack('!HHIIBBHHH', 40000, 9, 1, 0, 5 << 4, 0x04, 0, 0, 0)
pseudo = socket.inet_aton('127.0.0.1') * 2 + struct.pack('!BBH', 0, 6, len(tcp))
tcp = tcp[:16] + struct.pack('!H', csum(pseudo + tcp)) + tcp[18:]
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
try:
    s.sendto(tcp, ('127.0.0.1', 0))
except PermissionError:
    pass
"""


def _in_namespace(script: str) -> str:
    proc = subprocess.run(  # nosec B603 B607
        ['unshare', '-rn', 'sh', '-c', script],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def _nft_counters(exempt: bool) -> dict[str, int]:
    def rules(chain):
        text = _nft_rules(chain)
        if not exempt:
            text = text.replace('iif != "lo" ', '').replace('oif != "lo" ', '')
        return text

    ruleset = f"""table inet fwf_test {{
    chain probe {{
        type filter hook output priority -10;
        ct state invalid counter comment "probe"
    }}
    chain input {{
        type filter hook input priority filter; policy drop;
{rules('input')}        iif "lo" counter accept comment "lo_in"
    }}
    chain output {{
        type filter hook output priority filter; policy drop;
{rules('output')}        oif "lo" counter accept comment "lo_out"
    }}
}}
"""
    out = _in_namespace(
        'ip link set lo up && nft -f - <<"EOF"\n'
        f'{ruleset}EOF\n'
        f'python3 -I -c {shlex.quote(_SEND_RST)} && nft list ruleset'
    )
    counters = {}
    chain = None
    for line in out.splitlines():
        m = re.match(r'\s*chain (\w+)', line)
        if m:
            chain = m.group(1)
            continue
        m = re.search(r'counter packets (\d+)', line)
        if not m:
            continue
        if 'comment "probe"' in line:
            counters['probe'] = int(m.group(1))
        elif 'comment "lo_' in line:
            counters[f'lo_{chain}'] = int(m.group(1))
        elif 'ct state invalid' in line and line.rstrip().endswith('drop'):
            counters[f'invalid_{chain}'] = int(m.group(1))
    return counters


@pytest.mark.skipif(not CAN_ASK_NFT, reason=SKIP_REASON)
def test_nft_invalid_packet_on_loopback_reaches_the_policy():
    counters = _nft_counters(exempt=True)
    assert counters['probe'] >= 1
    assert counters['invalid_output'] == 0
    assert counters['invalid_input'] == 0
    assert counters['lo_output'] >= 1
    assert counters['lo_input'] >= 1


@pytest.mark.skipif(not CAN_ASK_NFT, reason=SKIP_REASON)
def test_nft_probe_hits_the_invalid_drop_without_the_exemption():
    counters = _nft_counters(exempt=False)
    assert counters['probe'] >= 1
    assert counters['invalid_output'] >= 1
    assert counters['lo_output'] == 0


def _ipt_counters(exempt: bool) -> dict[str, int]:
    rules = _ipt_rules()
    if not exempt:
        rules = rules.replace(' ! -i lo', '').replace(' ! -o lo', '')
    out = _in_namespace(
        'ip link set lo up && IPTABLES=iptables && '
        'iptables -t mangle -A OUTPUT -m conntrack --ctstate INVALID '
        '-m comment --comment probe && '
        'iptables -P INPUT DROP && iptables -P OUTPUT DROP && '
        f'{rules.strip()}\n'
        'iptables -A INPUT -i lo -m comment --comment lo_in -j ACCEPT && '
        'iptables -A OUTPUT -o lo -m comment --comment lo_out -j ACCEPT && '
        f'python3 -I -c {shlex.quote(_SEND_RST)} && '
        'iptables-save -c -t mangle && iptables-save -c -t filter'
    )
    counters = {}
    for line in out.splitlines():
        m = re.match(r'\[(\d+):\d+\] -A (\w+) (.*)', line)
        if not m:
            continue
        packets, chain, spec = int(m.group(1)), m.group(2), m.group(3)
        if 'probe' in spec:
            counters['probe'] = packets
        elif 'lo_in' in spec or 'lo_out' in spec:
            counters[f'lo_{chain}'] = packets
        elif 'INVALID' in spec and spec.endswith('-j DROP'):
            counters[f'invalid_{chain}'] = packets
    return counters


@pytest.mark.skipif(not CAN_ASK_IPTABLES, reason=SKIP_REASON_IPTABLES)
def test_ipt_invalid_packet_on_loopback_reaches_the_policy():
    counters = _ipt_counters(exempt=True)
    assert counters['probe'] >= 1
    assert counters['invalid_OUTPUT'] == 0
    assert counters['invalid_INPUT'] == 0
    assert counters['lo_OUTPUT'] >= 1
    assert counters['lo_INPUT'] >= 1


@pytest.mark.skipif(not CAN_ASK_IPTABLES, reason=SKIP_REASON_IPTABLES)
def test_ipt_probe_hits_the_invalid_drop_without_the_exemption():
    counters = _ipt_counters(exempt=False)
    assert counters['probe'] >= 1
    assert counters['invalid_OUTPUT'] >= 1
    assert counters['lo_OUTPUT'] == 0
