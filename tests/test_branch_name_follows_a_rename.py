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

"""A Branch rule jumps to the rule set it points at, under its current name.

A branch rule carries two references to its target: `branch_id`, which
identifies it, and `branch_name`, which is the chain the jump goes to.
Only the first is kept current - renaming a rule set in the editor writes
the new name onto the rule set and onto nothing else, and Firewall
Builder does not keep the second current either.

With a stale name iptables creates the named chain, leaves it empty and
jumps into it, so the branch does nothing in a script that activates
cleanly; nftables reports the rule and leaves it out.  Both are wrong
about a rule set that is compiled and reachable.
"""

import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import Firewall

FIXTURE = 'tests/fixtures/objects-for-regression-tests.fwb'


def _compile_with_a_renamed_branch(tmp_path, driver_class, name):
    """Compile firewall39 after renaming the rule set its rule 14 branches to."""
    db = firewallfabrik.core.DatabaseManager()
    db.load(FIXTURE)
    with db.session() as session:
        firewall = session.execute(
            sqlalchemy.select(Firewall).where(Firewall.name == 'firewall39')
        ).scalar_one()
        firewall_id = str(firewall.id)
        renamed = False
        for rule_set in firewall.rule_sets:
            if rule_set.name == 'rule6_branch':
                rule_set.name = 'renamed_branch'
                renamed = True
        assert renamed, 'the fixture no longer has the rule set this test renames'

    driver = driver_class(db)
    driver.wdir = str(tmp_path)
    driver.source_dir = 'tests/fixtures'
    driver.file_name_setting = name
    driver.run(cluster_id='', fw_id=firewall_id, single_rule_id='')
    return (tmp_path / name).read_text()


def test_the_iptables_jump_names_the_rule_set_that_was_compiled(tmp_path):
    from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt

    script = _compile_with_a_renamed_branch(tmp_path, CompilerDriver_ipt, 'fw.fw')
    assert '-j renamed_branch' in script
    assert 'rule6_branch' not in script


def test_the_nftables_jump_names_the_rule_set_that_was_compiled(tmp_path):
    from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft

    script = _compile_with_a_renamed_branch(tmp_path, CompilerDriver_nft, 'fw.fw')
    assert 'jump renamed_branch' in script
    assert 'rule6_branch' not in script
