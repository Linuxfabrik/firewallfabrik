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

"""Two rule sets do not rate-limit into one another's hash table.

The kernel finds the table of a rate limit by name alone:
``hashlimit_mt_check_common`` calls ``htable_find_get(net, name, family)``
and creates a table only when none of that name exists
(``net/netfilter/xt_hashlimit.c``).  A second rule naming an existing table
is accepted, its key, rate and expiry are dropped, and ``iptables -S``
prints back what it asked for - so nothing on the firewall says that one of
the two rules limits something else entirely.

Every rule set numbers its rules from zero, so the name Firewall Builder
derives from the position alone (``htable_rule_<position>``,
``PolicyCompiler_PrintRule.cpp:361``) is ambiguous the moment a branch rule
set has a rate-limited rule at the same position as the top one.
"""

from pathlib import Path

import pytest

from .conftest import FIXTURES_DIR, _compile

FIXTURE = FIXTURES_DIR / 'rate_limit_table_names.fwf'
FIREWALL = 'fw-rate-limit'

# Both rule sets rate-limit their rule 0: the top one by source address,
# the branch one by destination address.
TOP = 'htable_rule_0'
BRANCH = 'htable_Policy_second_0'


@pytest.fixture(scope='module')
def ipt_script(tmp_path_factory) -> str:
    tmp_path = tmp_path_factory.mktemp('rate-limit-ipt')
    return Path(_compile(FIXTURE, FIREWALL, tmp_path, 'ipt')).read_text()


@pytest.fixture(scope='module')
def nft_script(tmp_path_factory) -> str:
    tmp_path = tmp_path_factory.mktemp('rate-limit-nft')
    return Path(_compile(FIXTURE, FIREWALL, tmp_path, 'nft')).read_text()


def test_iptables_gives_the_branch_rule_set_a_table_of_its_own(ipt_script):
    assert f'--hashlimit-name {TOP} ' in ipt_script
    assert f'--hashlimit-name {BRANCH} ' in ipt_script


def test_iptables_keeps_the_reference_spelling_for_the_top_rule_set(ipt_script):
    """The short name is what Firewall Builder writes and is unambiguous.

    It also has to survive the 15 bytes revisions 0 and 1 of the match give
    it, and a truncated name says less than an ambiguous one.
    """
    assert 'htable_Policy_0' not in ipt_script


def test_nftables_gives_each_rule_set_a_meter_of_its_own(nft_script):
    assert 'meter htable_Policy_0 ' in nft_script
    assert f'meter {BRANCH} ' in nft_script


def test_neither_platform_reuses_one_name_for_both_rule_sets(ipt_script, nft_script):
    """Each rule set names one table, and the two names differ.

    One rule reaches several chains, so a name may well be written more
    than once - that is the same rule counting into its own table.  What
    must not happen is the two rule sets ending up on one name.
    """
    for script, keyword in ((ipt_script, '--hashlimit-name'), (nft_script, 'meter')):
        names = {
            line.split(keyword, 1)[1].split()[0]
            for line in script.splitlines()
            if keyword in line
        }
        assert len(names) == 2, names
