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

"""The installer hands the password to ssh/scp through SSH_ASKPASS.

OpenSSH never reads a password from stdin. It asks on the terminal - on
Windows a console the GUI user cannot see - so writing the password to
the process's stdin left scp waiting forever. The installer now points
SSH_ASKPASS at a helper that answers password prompts only, and refuses
anything else (such as an unknown host key question) so ssh fails with
a readable error instead of hanging.
"""

import os
import subprocess  # nosec B404
import sys
from pathlib import Path

import pytest

pytest.importorskip('PySide6')

from firewallfabrik.gui import _ssh_askpass
from firewallfabrik.gui import firewall_installer as fi


@pytest.fixture
def secret(monkeypatch):
    value = 'S3cr&t!pa$$ "q" %PATH% ^'
    monkeypatch.setenv(_ssh_askpass.SECRET_ENV, value)
    return value


@pytest.mark.parametrize(
    'prompt',
    [
        "root@192.168.1.1's password: ",
        "Enter passphrase for key '/root/.ssh/id_ed25519': ",
        'Password: ',
    ],
)
def test_helper_answers_password_prompts(secret, prompt, capfd):
    assert _ssh_askpass.main([prompt]) == 0
    assert capfd.readouterr().out == secret + '\n'


def test_helper_refuses_host_key_question(secret, capfd):
    prompt = (
        'The authenticity of host ... can not be established.\n'
        'Are you sure you want to continue connecting (yes/no/[fingerprint])? '
    )
    assert _ssh_askpass.main([prompt]) == 1
    assert capfd.readouterr().out == ''


def test_helper_without_secret_answers_nothing(monkeypatch, capfd):
    monkeypatch.delenv(_ssh_askpass.SECRET_ENV, raising=False)
    assert _ssh_askpass.main(["root@fw's password: "]) == 1
    assert capfd.readouterr().out == ''


@pytest.mark.skipif(os.name == 'nt', reason='POSIX shell wrapper')
def test_wrapper_runs_the_helper(tmp_path, secret):
    wrapper = _ssh_askpass.write_wrapper(tmp_path)
    assert wrapper is not None
    result = subprocess.run(  # nosec B603
        [str(wrapper), "root@fw's password: "],
        capture_output=True,
        check=False,
        env={**os.environ, _ssh_askpass.SECRET_ENV: secret},
    )
    assert result.returncode == 0
    assert result.stdout.decode() == secret + '\n'


def test_windows_wrapper_is_a_batch_file(tmp_path, monkeypatch):
    monkeypatch.setattr(_ssh_askpass, '_IS_WINDOWS', True)
    monkeypatch.setattr(_ssh_askpass.sys, 'executable', r'C:\Python\pythonw.exe')
    wrapper = _ssh_askpass.write_wrapper(tmp_path)
    assert wrapper.name == 'fwf-askpass.cmd'
    text = wrapper.read_text()
    assert text.startswith('@echo off')
    assert str(Path(_ssh_askpass.__file__).resolve()) in text
    assert text.rstrip().endswith('%*')


def _installer(password='', ssh_args='', scp_args=''):  # nosec B107
    return fi.FirewallInstaller(
        fi.InstallConfig(
            password=password,
            mgmt_address='192.0.2.1',
            ssh_args=ssh_args,
            scp_args=scp_args,
        ),
    )


@pytest.mark.usefixtures('qt_core_app')
def test_environment_points_ssh_at_the_helper():
    inst = _installer(password='pw')  # nosec B106
    try:
        env = inst._ssh_environment()
        wrapper = env.value('SSH_ASKPASS')
        assert Path(wrapper).exists()
        assert env.value('SSH_ASKPASS_REQUIRE') == 'force'
        assert env.value(_ssh_askpass.SECRET_ENV) == 'pw'
        assert env.contains('DISPLAY')
    finally:
        inst.terminate()
    assert not Path(wrapper).exists()


@pytest.mark.skipif(os.name == 'nt', reason='POSIX sessions')
@pytest.mark.usefixtures('qt_core_app')
def test_ssh_runs_without_a_controlling_terminal():
    """OpenSSH before 8.4 ignores SSH_ASKPASS_REQUIRE.

    With a terminal at hand it asks there and waits, which is what a GUI
    started from a terminal on RHEL 8 (OpenSSH 8.0) did.  In a session of
    its own it has no controlling terminal and takes the helper.
    """
    from PySide6.QtCore import QProcess

    inst = _installer(password='pw')  # nosec B106
    try:
        inst._start_process('true', [], env=inst._ssh_environment())
        flags = inst._process.unixProcessParameters().flags
        assert flags & QProcess.UnixProcessFlag.CreateNewSession
        inst._process.waitForFinished(5000)
    finally:
        inst.terminate()


@pytest.mark.usefixtures('qt_core_app')
def test_no_password_leaves_the_environment_alone():
    inst = _installer()
    assert inst._ssh_environment() is None
    assert inst._askpass_dir is None


@pytest.mark.usefixtures('qt_core_app')
@pytest.mark.parametrize('pack', ['_pack_scp_args', '_pack_ssh_args'])
def test_windows_without_password_does_not_wait_for_a_prompt(monkeypatch, pack):
    monkeypatch.setattr(fi, '_IS_WINDOWS', True)
    inst = _installer()
    if pack == '_pack_scp_args':
        args = inst._pack_scp_args('x.fw', '/etc/fw/x.fw')
    else:
        args = inst._pack_ssh_args('/etc/fw/x.fw')
    assert 'BatchMode=yes' in args


@pytest.mark.usefixtures('qt_core_app')
def test_batch_mode_respects_user_arguments(monkeypatch):
    monkeypatch.setattr(fi, '_IS_WINDOWS', True)
    args = _installer(scp_args='-o BatchMode=no')._pack_scp_args('a', 'b')
    assert 'BatchMode=yes' not in args


@pytest.mark.usefixtures('qt_core_app')
def test_batch_mode_only_without_password(monkeypatch):
    monkeypatch.setattr(fi, '_IS_WINDOWS', True)
    inst = _installer(password='pw')  # nosec B106
    assert 'BatchMode=yes' not in inst._pack_scp_args('a', 'b')


@pytest.fixture
def qt_core_app():
    from PySide6.QtCore import QCoreApplication

    return QCoreApplication.instance() or QCoreApplication(sys.argv[:1])
