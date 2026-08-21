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

"""The tool paths the Linux host settings dialog offers reach both scripts.

The generated nftables script calls `ip` and `logger` by variable, so a
firewall whose binaries live somewhere unusual needs those two paths as
much as an iptables firewall does.  They were declared irrelevant for
nftables - which greys the field out in the editor - and the driver read
a key of its own that no widget writes, so whatever was set there was
thrown away.
"""

import pathlib
import re

import pytest
import yaml

SRC = pathlib.Path(__file__).resolve().parent.parent / 'src' / 'firewallfabrik'
TEMPLATE = SRC / 'resources' / 'templates' / 'nftables' / 'script.sh.j2'

#: Shell variable -> the option key the Linux host settings dialog writes.
NFT_SCRIPT_TOOLS = {'IP': 'linux24_path_ip', 'LOGGER': 'linux24_path_logger'}


def _linux_schema():
    loaded = yaml.safe_load((SRC / 'platforms' / 'linux' / 'defaults.yaml').read_text())
    return loaded.get('options', loaded)


@pytest.mark.parametrize(('variable', 'key'), sorted(NFT_SCRIPT_TOOLS.items()))
def test_the_path_is_offered_for_nftables(variable, key):
    entry = _linux_schema()[key]
    assert entry['supported'] is True
    assert entry['nftables_supported'] is True, (
        f'the generated nftables script calls ${variable}, so the editor '
        f'must not grey {key} out'
    )


@pytest.mark.parametrize('variable', sorted(NFT_SCRIPT_TOOLS))
def test_the_template_takes_the_path_from_a_variable(variable):
    """A hardcoded path in the template cannot be overridden at all."""
    template = TEMPLATE.read_text()
    assignment = re.search(rf'^{variable}="(.*)"$', template, re.M)
    assert assignment is not None, f'{variable} is not assigned in the template'
    assert assignment.group(1).startswith('{{'), (
        f'{variable} is hardcoded to {assignment.group(1)!r}'
    )


def test_the_driver_prefers_the_key_the_editor_writes():
    """`ip_path` is the nftables schema's own key and has no widget."""
    driver = (SRC / 'platforms' / 'nftables' / '_compiler_driver.py').read_text()
    block = driver[driver.index('ip_path = (') :]
    block = block[: block.index("or 'ip'")]
    assert block.index("'linux24_path_ip'") < block.index("'ip_path'")
