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

"""Hand every generated nftables ruleset to nft itself.

The expected-output tests guard against *changes* in the output; they never
ask whether the result loads. A ruleset nft refuses is refused as a whole,
so one bad rule leaves the firewall with whatever it had before - or, worse,
with nothing. This test closes that gap for the checked-in expected output,
which is what every other test compares against.

``nft --check`` parses and evaluates the ruleset without installing it, but
it cannot initialise its cache without CAP_NET_ADMIN, so it runs inside a
private network namespace. Where that namespace cannot be created the test
skips; see ``tests/tool_probe.py``.
"""

import re
import subprocess  # nosec B404
from pathlib import Path

import pytest

from tests.tool_probe import CAN_ASK_NFT, SKIP_REASON

EXPECTED_OUTPUT_DIR = Path(__file__).parent / 'expected-output' / 'nft'

# The generated script carries the ruleset in a heredoc.
_NFT_RULES_RE = re.compile(r"<<'NFT_RULES'\n(.*?)\nNFT_RULES", re.S)

# These two hold a rule matching a DNS name written out literally, from
# before the compiler learned to fill a named set at activation time
# instead.  They depend on what the name resolved to when they were
# generated, so they are deliberately not regenerated, and nft refuses a
# name with more than one address.
_DNS_DEPENDENT = {'firewall33.fw', 'firewall33-1.fw'}

pytestmark = pytest.mark.skipif(not CAN_ASK_NFT, reason=SKIP_REASON)


def _rulesets() -> list[Path]:
    return sorted(
        f for f in EXPECTED_OUTPUT_DIR.rglob('*.fw') if f.name not in _DNS_DEPENDENT
    )


@pytest.mark.parametrize(
    'ruleset_path',
    _rulesets(),
    ids=lambda p: f'{p.parent.name}/{p.stem}',
)
def test_generated_ruleset_loads(ruleset_path, tmp_path):
    body = _NFT_RULES_RE.search(ruleset_path.read_text())
    if body is None:
        pytest.skip('firewall compiles to no nftables rules')

    ruleset = tmp_path / 'ruleset.nft'
    ruleset.write_text(body.group(1) + '\n')

    proc = subprocess.run(  # nosec B603 B607
        ['unshare', '-rn', 'nft', '--check', '-f', str(ruleset)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, (
        f'nft refuses the ruleset of {ruleset_path}:\n{proc.stderr}'
    )
