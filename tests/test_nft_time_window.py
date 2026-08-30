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

"""The calendar window of a Time object, on nftables.

`meta time` takes either a plain number of seconds, which nft reads as
UTC, or a **quoted** date, from which it subtracts the offset of the host
that loads the ruleset (netfilter nftables src/meta.c: `parse_iso_date`
and `date_type_parse`).  Which of the two fwf writes follows the "use
kernel timezone" setting, the same choice `meta hour` makes.

An unquoted date is a syntax error, and nft loads a ruleset atomically:
one such rule costs the whole policy.
"""

import copy
import re
import subprocess  # nosec B404
from pathlib import Path

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import Firewall
from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft
from tests.tool_probe import CAN_ASK_NFT, SKIP_REASON

from .conftest import FIXTURES_DIR

FIXTURE = FIXTURES_DIR / 'objects-for-regression-tests.fwb'

# Both carry a Time object that pins a calendar window as well as a time
# of day and a set of weekdays.
FIREWALLS = ('firewall4', 'firewall61-1.4')

# Everything between `meta time ` and the statement that follows it.
_META_TIME = re.compile(
    r'meta time (.*?)(?= meta | counter | log | accept| drop| reject| jump| goto'
    r'| queue| return|$)'
)

#: The two shapes nft's grammar takes, and no third.
_QUOTED_DATES = re.compile(
    r'^"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"'
    r'-"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"$'
)
_EPOCH_SECONDS = re.compile(r'^\d+-\d+$')


def _compile(tmp_path: Path, firewall: str, *, kerneltz: bool) -> str:
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(FIXTURE))
    with db.session() as session:
        fw = session.execute(
            sqlalchemy.select(Firewall).where(Firewall.name == firewall)
        ).scalar_one()
        options = copy.deepcopy(fw.options or {})
        options['use_kerneltz'] = kerneltz
        fw.options = options
        fw_id = str(fw.id)

    driver = CompilerDriver_nft(db)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(FIXTURE.parent)
    driver.file_name_setting = f'{firewall}.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    return (tmp_path / f'{firewall}.fw').read_text()


def _ruleset(script: str) -> str:
    body = script.split("<<'NFT_RULES'\n", 1)[1]
    return body.split('\nNFT_RULES', 1)[0]


def _windows(script: str) -> list[str]:
    return [
        match
        for line in _ruleset(script).splitlines()
        for match in _META_TIME.findall(line)
    ]


@pytest.mark.parametrize('firewall', FIREWALLS)
def test_a_date_reaches_the_ruleset_quoted(tmp_path, firewall):
    """`meta hour` is quoted and `meta time` has to be too."""
    windows = _windows(_compile(tmp_path, firewall, kerneltz=True))
    assert windows
    for window in windows:
        assert _QUOTED_DATES.match(window), window


@pytest.mark.parametrize('firewall', FIREWALLS)
def test_without_the_kernel_timezone_it_is_a_number(tmp_path, firewall):
    """A bare number is what nft reads as UTC, which is what iptables
    compares against without ``--kerneltz``."""
    windows = _windows(_compile(tmp_path, firewall, kerneltz=False))
    assert windows
    for window in windows:
        assert _EPOCH_SECONDS.match(window), window


@pytest.mark.skipif(not CAN_ASK_NFT, reason=SKIP_REASON)
@pytest.mark.parametrize('firewall', FIREWALLS)
@pytest.mark.parametrize('kerneltz', (True, False))
def test_nft_accepts_the_ruleset(tmp_path, firewall, kerneltz):
    ruleset = tmp_path / 'ruleset.nft'
    ruleset.write_text(_ruleset(_compile(tmp_path, firewall, kerneltz=kerneltz)))
    proc = subprocess.run(  # nosec B603 B607
        ['unshare', '-rn', 'nft', '--check', '--file', str(ruleset)],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    # A fixture may name a host that does not resolve here; that is a
    # property of the corpus, not of the compiler.
    errors = [
        line
        for line in proc.stderr.splitlines()
        if 'Name or service not known' not in line
    ]
    assert not errors, '\n'.join(errors)
