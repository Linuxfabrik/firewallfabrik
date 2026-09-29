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

"""The kernel-hardening settings that have a copy per interface.

Everything under ``/proc/sys/net/ipv{4,6}/conf/`` exists once per
interface next to the one under ``all``, and the kernel combines the two
rather than reading ``all`` on its own
(``Documentation/networking/ip-sysctl.rst``):

* ``rp_filter`` is the **maximum** of ``conf/{all,interface}``
* ``log_martians`` is their **OR**
* ``accept_source_route`` is their **AND**
* ``accept_redirects`` is their AND while the interface forwards and
  their OR while it does not

So writing ``conf/all`` alone takes effect in one direction only, and the
direction that is lost is the one an administrator picks for safety:
"reverse path filter off" and "accept ICMP redirects off" do nothing on a
distribution that sets the per-interface copy, which every current one
does.  Verified on a live kernel: with ``conf/dummy0/accept_redirects``
at 1, writing 0 into ``conf/all/accept_redirects`` leaves dummy0 at 1.

The generated script therefore writes every copy.  The glob covers
``all``, ``default`` and each interface the box has at activation time;
``default`` is what an interface created later starts from.
"""

import copy
from pathlib import Path

import pytest
import sqlalchemy

from firewallfabrik.core import DatabaseManager
from firewallfabrik.core.objects import Firewall
from firewallfabrik.driver._configlet import Configlet
from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt
from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft

# The setting, the family, and the option value written into it.
_CONF_SETTINGS = (
    ('rp_filter', 'ipv4', 'linux24_rp_filter'),
    ('accept_source_route', 'ipv4', 'linux24_accept_source_route'),
    ('accept_source_route', 'ipv6', 'linux24_accept_source_route'),
    ('accept_redirects', 'ipv4', 'linux24_accept_redirects'),
    ('accept_redirects', 'ipv6', 'linux24_accept_redirects'),
    ('log_martians', 'ipv4', 'linux24_log_martians'),
)


@pytest.fixture(scope='module')
def kernel_vars():
    """Every conf/ setting switched on, so each line is rendered."""
    configlet = Configlet('linux24', 'kernel_vars')
    configlet.remove_comments()
    configlet.collapse_empty_strings(True)
    for setting, family, option in _CONF_SETTINGS:
        prefix = 'if_linux24' if family == 'ipv4' else 'if'
        name = f'{prefix}_{setting}' if family == 'ipv4' else f'if_{setting}_v6'
        configlet.set_variable(name, 1)
        configlet.set_variable(option, '0')
    return configlet.expand()


@pytest.mark.parametrize(
    ('setting', 'family'),
    [(setting, family) for setting, family, _ in _CONF_SETTINGS],
)
def test_every_copy_of_the_setting_is_written(kernel_vars, setting, family):
    glob = f'/proc/sys/net/{family}/conf/*/{setting}'
    assert glob in kernel_vars, f'{family} {setting} is not written per interface'


@pytest.mark.parametrize(
    ('setting', 'family'),
    [(setting, family) for setting, family, _ in _CONF_SETTINGS],
)
def test_the_all_copy_alone_is_not_enough(kernel_vars, setting, family):
    """Writing only ``conf/all`` is what the kernel does not act on."""
    assert f'> /proc/sys/net/{family}/conf/all/{setting}' not in kernel_vars


def test_a_setting_without_a_per_interface_copy_is_left_alone():
    """`icmp_echo_ignore_all` and the tcp_* knobs are global, not per device."""
    configlet = Configlet('linux24', 'kernel_vars')
    configlet.remove_comments()
    configlet.collapse_empty_strings(True)
    configlet.set_variable('if_linux24_icmp_echo_ignore_all', 1)
    configlet.set_variable('linux24_icmp_echo_ignore_all', '1')
    rendered = configlet.expand()
    assert 'echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all' in rendered
    assert 'for f in' not in rendered


@pytest.mark.parametrize('platform', ['iptables', 'nftables'])
def test_loose_reverse_path_filtering_reaches_the_script(tmp_path, platform):
    """rp_filter 2 is loose mode (RFC 3704), for asymmetric routing.

    The value goes through unchanged into every copy of the setting.
    """
    driver_class = CompilerDriver_ipt if platform == 'iptables' else CompilerDriver_nft
    db = DatabaseManager()
    db.load(str(Path(__file__).parent / 'fixtures' / 'basic_accept_deny.fwf'))
    with db.session() as session:
        fw = session.execute(
            sqlalchemy.select(Firewall).where(Firewall.name == 'fw-test'),
        ).scalar_one()
        options = copy.deepcopy(fw.options or {})
        options['linux24_rp_filter'] = '2'
        fw.options = options
        fw_id = str(fw.id)
    driver = driver_class(db)
    driver.wdir = str(tmp_path)
    driver.file_name_setting = 'fw-test.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    script = Path(driver.file_names[fw_id]).read_text()
    assert (
        'for f in /proc/sys/net/ipv4/conf/*/rp_filter ; do echo 2 > "$f" ; done'
        in script
    )
