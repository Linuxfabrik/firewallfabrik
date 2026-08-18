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

"""What the caller learns when the driver itself refuses to compile.

The driver collects the messages of every sub-compiler into
``all_errors`` / ``all_warnings``, and that pair is what `fwf-ipt`,
`fwf-nft` and the GUI read: the CLI counts a firewall as failed when
``all_errors`` is non-empty or the driver returned a string, and exits 1
only then.

Its own messages had no such collector.  `BaseCompiler.error` keeps them
for the compiler that is running, and the driver is not one - so a
condition it finds before the first sub-compiler even starts wrote no
script, said nothing, and was counted as a success.
"""

import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import Firewall
from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt
from tests.conftest import FIXTURES_DIR


def _compile_with(options, tmp_path):
    """Compile fw-prolog-epilog3 with *options* merged into its own."""
    fixture = FIXTURES_DIR / 'compiler-tests.fwf'
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(fixture))
    with db.session() as session:
        fw = session.execute(
            sqlalchemy.select(Firewall).where(Firewall.name == 'fw-prolog-epilog3')
        ).scalar_one()
        fw_id = str(fw.id)
        fw.options = {**(fw.options or {}), **options}

    driver = CompilerDriver_ipt(db)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(fixture.parent)
    driver.file_name_setting = 'fw-prolog-epilog3.fw'
    result = driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    return driver, result


def test_a_refused_combination_of_options_is_reported(tmp_path):
    """The prolog cannot run after the flush when restore installs the rules.

    The driver has refused this since it was written, and wrote no script
    for it - in silence, which left the firewall running whatever it was
    running before and the operator with an exit code of 0.
    """
    driver, result = _compile_with({'use_iptables_restore': True}, tmp_path)

    assert not (tmp_path / 'fw-prolog-epilog3.fw').exists()
    assert driver.all_errors
    assert 'iptables-restore' in driver.all_errors[0]
    # What the CLI decides on.
    assert driver.all_errors or result


def test_the_same_firewall_compiles_without_that_combination(tmp_path):
    """Guard the premise: the refusal is the option pair, not the fixture."""
    driver, result = _compile_with({'use_iptables_restore': False}, tmp_path)

    assert (tmp_path / 'fw-prolog-epilog3.fw').exists()
    assert not driver.all_errors
    assert not result
