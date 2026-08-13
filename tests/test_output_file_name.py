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

"""Where the generated script is written, and who decides it.

Three tiers, the way fwbuilder resolves them
(CompilerDriver::getOutputFileNameInternal): ``-o`` on the command line
wins, then the firewall's own "Compiler > Output file name", then the name
derived from the firewall object.  The middle tier was missing, so the GUI
- which passes the setting through as ``-o`` itself - and a compile from
the command line disagreed about the file name.
"""

from pathlib import Path

import pytest

from firewallfabrik.driver._compiler_driver import CompilerDriver
from firewallfabrik.platforms._defaults import get_platform_defaults


class _Firewall:
    id = 'fw-id'

    def __init__(self, output_file=None) -> None:
        self.name = 'fw test'
        self._options = {} if output_file is None else {'output_file': output_file}

    def get_option(self, key, default=None):
        if key == 'output_file':
            return self._options.get('output_file', '')
        return {'firewall_dir': '/etc/fw', 'script_name_on_firewall': ''}.get(key, '')


def _resolve(output_file=None, cli=''):
    driver = CompilerDriver(None)
    driver.wdir = 'out-dir'
    driver.file_name_setting = cli
    fw = _Firewall(output_file)
    driver.determine_output_file_names(fw)
    return driver.file_names[str(fw.id)], driver.remote_file_names[str(fw.id)]


def test_the_object_name_is_the_fallback():
    local, _remote = _resolve()
    assert Path(local).name == 'fw_test.fw'


def test_the_firewall_setting_is_used_when_there_is_no_o():
    local, _remote = _resolve(output_file='rc.firewall.local')
    assert Path(local).name == 'rc.firewall.local'


def test_o_on_the_command_line_still_wins():
    local, _remote = _resolve(output_file='rc.firewall.local', cli='given.fw')
    assert Path(local).name == 'given.fw'


def test_a_path_in_the_setting_does_not_reach_the_remote_name():
    """The remote name is built from the basename, as it always was."""
    _local, remote = _resolve(output_file='/home/admin/fw/vml010.fw')
    assert remote == '/etc/fw/vml010.fw'


@pytest.mark.parametrize('platform', ['iptables', 'nftables'])
def test_the_declared_default_is_empty(platform):
    """A non-empty default would send every firewall to the same file.

    The description has always said "leave empty to use the default name
    derived from the firewall object name", which a default of its own
    made impossible: `get_option` never returns empty then.
    """
    entry = get_platform_defaults(platform)['output_file']
    assert entry['default'] == ''
    assert entry['placeholder']
