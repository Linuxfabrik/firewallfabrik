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

"""The nftables statement an iptables Custom-action target translates to.

Firewall Builder had one field for the Custom action and no second Linux
platform to need another, so every rule imported from a `.fwb` file
carries an iptables target and nothing else.  The iptables compiler
writes it; the nftables one used to leave the rule out, so switching a
firewall from one packet filter to the other quietly dropped rules.

What is translated is what netfilter's own translator translates, and the
spelling is taken from there.  The table below is the expectation, and
two tests check it against the netfilter tools themselves where they are
installed: `iptables-translate` says what the target becomes, and `nft`
says the result parses.
"""

import shutil
import subprocess  # nosec B404

import pytest

from firewallfabrik.platforms.linux._netfilter import (
    custom_action_nftables_statement,
)
from tests.tool_probe import CAN_ASK_NFT, SKIP_REASON

#: Every target this translates, and what it becomes.  Derived from the
#: `xlate` function of each extension and checked against the tool below.
TRANSLATIONS = {
    '-j CLASSIFY --set-class 0:0': 'meta priority set none',
    '-j CLASSIFY --set-class 1:11': 'meta priority set 1:11',
    '-j CLASSIFY --set-class ffff:ffff': 'meta priority set root',
    '-j CONNMARK --and-mark 64': 'ct mark set ct mark and 0x40',
    '-j CONNMARK --or-mark 64': 'ct mark set ct mark or 0x40',
    '-j CONNMARK --restore-mark': 'meta mark set ct mark',
    '-j CONNMARK --save-mark': 'ct mark set mark',
    '-j CONNMARK --set-mark 0x16': 'ct mark set 0x16',
    '-j CONNMARK --xor-mark 64': 'ct mark set ct mark xor 0x40',
    '-j MARK --and-mark 64': 'meta mark set mark and 0x40',
    '-j MARK --or-mark 64': 'meta mark set mark or 0x40',
    '-j MARK --set-mark 0x40/0x32': 'meta mark set mark and 0xffffff8d xor 0x40',
    '-j MARK --set-mark 64': 'meta mark set 0x40',
    '-j MARK --set-xmark 0x40/0x32': 'meta mark set mark and 0xffffffcd xor 0x40',
    '-j MARK --xor-mark 64': 'meta mark set mark xor 0x40',
    '-j NFQUEUE --queue-balance 0:3': 'queue num 0-3',
    '-j NFQUEUE --queue-balance 0:3 --queue-cpu-fanout': 'queue num 0-3 fanout',
    '-j NFQUEUE --queue-num 0 --queue-bypass': 'queue num 0 bypass',
    '-j NFQUEUE --queue-num 30': 'queue num 30',
    '-j NOTRACK': 'notrack',
    '-j TCPMSS --clamp-mss-to-pmtu': 'tcp option maxseg size set rt mtu',
    '-j TCPMSS --set-mss 1400': 'tcp option maxseg size set 1400',
    '-j TRACE': 'nftrace set 1',
}

#: The one entry where this deliberately differs from what
#: `iptables-translate` prints.  `connmark_tg_xlate` writes the masked
#: form as `ct mark set ct mark xor <value> and <~mask>`, and nft applies
#: the two in the order they are written: measured with
#: `nft --debug=netlink`, that is `( mark & 0xffffffff ) ^ 0x0` - a
#: statement that changes nothing.  `mark_tg_xlate` writes the same
#: arithmetic the other way round and means `(old & ~mask) ^ mark`, which
#: is what `mark_tg` in the kernel does, so both targets get that one.
CONNMARK_MASKED = '-j CONNMARK --set-mark 0x40/0x32'
CONNMARK_MASKED_CORRECT = 'ct mark set ct mark and 0xffffff8d xor 0x40'
CONNMARK_MASKED_AS_IPTABLES_WRITES_IT = 'ct mark set ct mark xor 0x40 and 0xffffff8d'

#: Targets with no nftables statement: one that never was in mainline
#: netfilter, one whose translation depends on the address family a
#: Custom action does not carry, one whose IPv4 half netfilter's own
#: translator has commented out, and text that is no `-j` at all.
NOT_TRANSLATED = [
    '-j TARPIT',
    '-j DSCP --set-dscp 26',
    '-j TEE --gateway 192.0.2.2',
    '-j ULOG --ulog-nlgroup 1',
    'tcp option maxseg size set 1400',
    '-m tcp --dport 22 -j ACCEPT',
    '-j TCPMSS',
    '-j TCPMSS --set-mss 70000',
    '-j CLASSIFY --set-class 1',
    '-j NFQUEUE --queue-balance 3:0',
    '',
]

HAS_IPTABLES_TRANSLATE = shutil.which('iptables-translate') is not None


@pytest.mark.parametrize('target', sorted(TRANSLATIONS))
def test_every_target_translates_to_what_the_table_says(target):
    assert custom_action_nftables_statement(target) == TRANSLATIONS[target]


@pytest.mark.parametrize('target', NOT_TRANSLATED)
def test_a_target_with_no_statement_is_refused(target):
    assert custom_action_nftables_statement(target) is None


def test_the_masked_connmark_form_is_the_one_that_does_the_arithmetic():
    assert custom_action_nftables_statement(CONNMARK_MASKED) == CONNMARK_MASKED_CORRECT


@pytest.mark.skipif(not HAS_IPTABLES_TRANSLATE, reason='needs iptables-translate')
@pytest.mark.parametrize('target', sorted(TRANSLATIONS))
def test_the_table_is_what_iptables_translate_prints(target):
    """Re-derive the expectation from the tool rather than trusting it."""
    printed = subprocess.run(  # nosec B603
        [
            shutil.which('iptables-translate') or 'iptables-translate',
            '-t',
            'mangle',
            '-A',
            'PREROUTING',
            *target.split(),
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    prefix = "nft 'add rule ip mangle PREROUTING counter "
    assert printed.startswith(prefix), printed
    assert printed[len(prefix) :].rstrip("'").strip() == TRANSLATIONS[target]


@pytest.mark.skipif(not HAS_IPTABLES_TRANSLATE, reason='needs iptables-translate')
def test_the_masked_connmark_form_is_still_the_one_netfilter_writes():
    """The divergence is a bug in the tool, so it has to stay measured."""
    printed = subprocess.run(  # nosec B603
        [
            shutil.which('iptables-translate') or 'iptables-translate',
            '-t',
            'mangle',
            '-A',
            'PREROUTING',
            *CONNMARK_MASKED.split(),
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert CONNMARK_MASKED_AS_IPTABLES_WRITES_IT in printed


@pytest.mark.skipif(not CAN_ASK_NFT, reason=SKIP_REASON)
def test_every_statement_parses():
    """A statement nft refuses costs the whole ruleset, not the rule."""
    rules = '\n'.join(
        f'        counter {statement}'
        for statement in sorted({*TRANSLATIONS.values(), CONNMARK_MASKED_CORRECT})
    )
    ruleset = f'table ip fwf_probe {{\n    chain c {{\n{rules}\n    }}\n}}\n'
    proc = subprocess.run(  # nosec B603
        [
            shutil.which('unshare') or 'unshare',
            '-rn',
            'nft',
            '--check',
            '-f',
            '-',
        ],
        input=ruleset,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
