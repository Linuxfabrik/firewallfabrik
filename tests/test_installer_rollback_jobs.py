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

"""The installer activates with the rollback timer and confirms separately.

With the timer the script goes to ``<script>.new``, is activated with
``try``, and is confirmed - and only then moved to the path the firewall
boots from - by a job of its own, which opens a new connection.
"""

import pytest

pytest.importorskip('PySide6')

from firewallfabrik.gui import firewall_installer as fi


def _config(**kwargs):
    defaults = {
        'firewall_dir': '/etc/fw',
        'remote_script': '/etc/fw/fwf.sh',
        'rollback_timeout': 45,
        'script_path': '/nonexistent/fwf.sh',
    }
    defaults.update(kwargs)
    return fi.InstallConfig(**defaults)


@pytest.mark.parametrize('user', ['root', 'admin'])
def test_rollback_stages_tries_and_confirms(user):
    jobs = fi.build_job_list(_config(user=user))

    assert [job.job_type for job in jobs] == [
        fi.JobType.COPY_FILE,
        fi.JobType.ACTIVATE_POLICY,
        fi.JobType.CONFIRM_POLICY,
    ]
    assert jobs[0].arg2 == '/etc/fw/fwf.sh.new'
    assert '/etc/fw/fwf.sh.new try 45' in jobs[1].arg1
    assert 'fwf.sh.new confirm' not in jobs[1].arg1
    assert '/etc/fw/fwf.sh.new confirm' in jobs[2].arg1
    assert 'mv -f /etc/fw/fwf.sh.new /etc/fw/fwf.sh' in jobs[2].arg1


@pytest.mark.parametrize('user', ['root', 'admin'])
def test_without_rollback_the_script_is_activated_in_place(user):
    jobs = fi.build_job_list(_config(user=user, rollback=False))

    assert [job.job_type for job in jobs] == [
        fi.JobType.COPY_FILE,
        fi.JobType.ACTIVATE_POLICY,
    ]
    assert jobs[0].arg2 == '/etc/fw/fwf.sh'
    assert ' try ' not in jobs[1].arg1


def test_a_custom_activation_command_gets_no_timer():
    """The timer cannot be put around a command the installer did not write."""
    jobs = fi.build_job_list(_config(activation_cmd='/usr/local/bin/deploy'))

    assert jobs[0].arg2 == '/etc/fw/fwf.sh'
    assert [job.arg1 for job in jobs[1:]] == ['/usr/local/bin/deploy']


def test_the_confirmation_opens_a_connection_of_its_own():
    """A multiplexed channel of the activating session would prove nothing."""
    installer = fi.FirewallInstaller(_config())
    args = installer._pack_ssh_args(
        'true', extra=['-o', 'ControlMaster=no', '-o', 'ControlPath=none']
    )

    assert args.index('ControlPath=none') < args.index('-l')
