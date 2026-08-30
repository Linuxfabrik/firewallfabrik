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

The namespace also gets a passwd and a group file of its own, holding
every name a ``meta skuid`` / ``meta skgid`` in the ruleset uses: nft
looks the name up with ``getpwnam`` while it parses the rule and refuses
the whole ruleset when the answer is no (netfilter nftables src/meta.c,
``uid_type_parse``). The firewall those rules are for has that user; the
machine running the suite has no reason to, and without this the test
would report a healthy ruleset for a property of the host.
"""

import re
import subprocess  # nosec B404
from pathlib import Path

import pytest

from tests.tool_probe import CAN_ASK_NFT, SKIP_REASON

EXPECTED_OUTPUT_DIR = Path(__file__).parent / 'expected-output' / 'nft'

# The generated script carries the ruleset in a heredoc.
_NFT_RULES_RE = re.compile(r"<<'NFT_RULES'\n(.*?)\nNFT_RULES", re.S)

# A user or group a rule matches on, named rather than numbered.
_SOCKET_OWNER_RE = re.compile(r'meta (skuid|skgid) (?:!= )?([A-Za-z_][\w.-]*)')

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

    passwd, group = _user_database(body.group(1), tmp_path)
    script = (
        f"mount --bind '{passwd}' /etc/passwd\n"
        f"mount --bind '{group}' /etc/group\n"
        f"nft --check -f '{ruleset}'\n"
    )
    proc = subprocess.run(  # nosec B603 B607
        ['unshare', '-rnm', 'bash', '-c', script],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, (
        f'nft refuses the ruleset of {ruleset_path}:\n{proc.stderr}'
    )


def _user_database(ruleset_text: str, tmp_path) -> tuple[Path, Path]:
    """Return a passwd and a group file that know every name the ruleset uses."""
    passwd = tmp_path / 'passwd'
    group = tmp_path / 'group'
    passwd_lines = Path('/etc/passwd').read_text().splitlines()
    group_lines = Path('/etc/group').read_text().splitlines()
    known_users = {line.split(':', 1)[0] for line in passwd_lines}
    known_groups = {line.split(':', 1)[0] for line in group_lines}
    next_id = 60000
    for keyword, name in _SOCKET_OWNER_RE.findall(ruleset_text):
        if keyword == 'skuid' and name not in known_users:
            passwd_lines.append(
                f'{name}:x:{next_id}:{next_id}::/nonexistent:/bin/false'
            )
            known_users.add(name)
            next_id += 1
        elif keyword == 'skgid' and name not in known_groups:
            group_lines.append(f'{name}:x:{next_id}:')
            known_groups.add(name)
            next_id += 1
    passwd.write_text('\n'.join(passwd_lines) + '\n')
    group.write_text('\n'.join(group_lines) + '\n')
    return passwd, group
