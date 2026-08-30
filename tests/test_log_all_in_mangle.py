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

""""Log all rules" reaches the mangle table on both platforms.

``clearLogInMangle`` turns a rule's own logging off in the mangle pass, so
a rule compiled into both tables is logged once.  The global "log all
rules" setting is applied *after* it (``PolicyCompiler_ipt::compile``:
clearLogInMangle at 4406, Logging1 at 4412), so it puts the logging back -
which is what the setting asks for.

The nftables pipeline had the two the other way round, so a firewall that
tags or classifies logged its mangle rules on iptables and not on
nftables.
"""

from pathlib import Path

import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import Firewall

FIXTURE = Path(__file__).parent / 'fixtures' / 'basic_accept_deny.fwf'
# Rule 4 of the fixture assigns a traffic class, so it is the rule that
# reaches the mangle table.
CLASSIFYING_RULE = 'Rule 4'


def _compile_with_log_all(tmp_path, platform):
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(FIXTURE))
    with db.session() as session:
        fw = session.execute(
            sqlalchemy.select(Firewall).where(Firewall.name == 'fw-test')
        ).scalar_one()
        fw_id = str(fw.id)
        options = dict(fw.options or {})
        options['log_all'] = True
        fw.options = options
        session.commit()

    if platform == 'ipt':
        from firewallfabrik.platforms.iptables._compiler_driver import (
            CompilerDriver_ipt as Driver,
        )
    else:
        from firewallfabrik.platforms.nftables._compiler_driver import (
            CompilerDriver_nft as Driver,
        )
    driver = Driver(db)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(FIXTURE.parent)
    driver.file_name_setting = 'fw-test.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    return (tmp_path / 'fw-test.fw').read_text()


def _mangle_block(script, platform):
    """Return the part of *script* that installs the mangle rules."""
    if platform == 'ipt':
        return '\n'.join(
            line for line in script.splitlines() if '-t mangle' in line
        )
    start = script.find('table ip fwf_mangle {\n    chain')
    assert start != -1, 'the nftables script has no mangle table'
    return script[start : script.find('\n}\n', start)]


def test_the_classifying_rule_logs_in_the_mangle_table(tmp_path):
    for platform in ('ipt', 'nft'):
        out = tmp_path / platform
        out.mkdir()
        block = _mangle_block(_compile_with_log_all(out, platform), platform)
        assert 'RULE 4 -- CONTINUE' in block, (
            f'{platform} does not log the classifying rule in the mangle table'
        )


def test_the_class_is_still_assigned(tmp_path):
    """The log must not have taken the statement it travels with."""
    out = tmp_path / 'nft'
    out.mkdir()
    block = _mangle_block(_compile_with_log_all(out, 'nft'), 'nft')
    assert 'meta priority set 1:10' in block
