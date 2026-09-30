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

"""Firewall installer engine — deploys compiled scripts via SSH/SCP."""

import logging
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from enum import IntEnum, auto
from html import escape as _html_escape
from pathlib import Path
from typing import NamedTuple

from PySide6.QtCore import (
    QByteArray,
    QObject,
    QProcess,
    QProcessEnvironment,
    QSettings,
    Signal,
)

from firewallfabrik.driver._configlet import Configlet
from firewallfabrik.gui import _ssh_askpass

logger = logging.getLogger(__name__)

_IS_WINDOWS = os.name == 'nt'


def _esc(text):
    """HTML-escape without mangling apostrophes."""
    return _html_escape(str(text), quote=False)


class JobType(IntEnum):
    COPY_FILE = auto()
    ACTIVATE_POLICY = auto()
    CONFIRM_POLICY = auto()
    RUN_EXTERNAL_SCRIPT = auto()


class InstallJob(NamedTuple):
    job_type: JobType
    arg1: str
    arg2: str


@dataclass
class InstallConfig:
    """Per-firewall installation configuration."""

    user: str = 'root'
    password: str = ''
    mgmt_address: str = ''
    firewall_dir: str = '/etc/fw'
    ssh_args: str = ''
    scp_args: str = ''
    activation_cmd: str = ''
    install_script: str = ''
    install_script_args: str = ''
    verbose: bool = False
    quiet: bool = False
    copy_fwb: bool = False
    batch_install: bool = False
    rollback: bool = True
    rollback_timeout: int = 60
    # Set by the dialog / caller before running jobs.
    script_path: str = ''
    remote_script: str = ''
    fwb_file: str = ''
    firewall_name: str = ''
    working_dir: str = '.'
    alt_address: str = ''

    # Filled in by build_job_list.
    job_list: list[InstallJob] = field(default_factory=list)


# Manifest marker prefix used by compilers.
_MANIFEST_PREFIX = '# files: '


def read_manifest(script_path: str) -> dict[str, str]:
    """Parse ``# files:`` manifest lines from a compiled script.

    Returns a dict mapping local file name to a remote file name.
    The main script is marked with ``*`` in the manifest.

    Format::

        # files: [*]local_name [remote_name]

    If the remote name is missing, it defaults to the local name.
    """
    result: dict[str, str] = {}
    try:
        text = Path(script_path).read_text(encoding='utf-8', errors='replace')
    except OSError:
        return result

    for line in text.splitlines():
        if not line.startswith(_MANIFEST_PREFIX):
            continue
        rest = line[len(_MANIFEST_PREFIX) :].strip()
        if not rest:
            continue

        # Strip the main-script marker.
        main = rest.startswith('*')
        if main:
            rest = rest[1:].lstrip()

        parts = rest.split(None, 1)
        local_name = parts[0]
        remote_name = parts[1] if len(parts) > 1 else local_name
        result[local_name] = remote_name

    return result


def uses_rollback(config: InstallConfig) -> bool:
    """Whether this installation activates with the rollback timer.

    A custom activation command or installation script says itself how
    the policy is activated, so the timer cannot be put around it.
    """
    return config.rollback and not config.activation_cmd and not config.install_script


def get_activation_cmd(config: InstallConfig, confirm: bool = False) -> str:
    """Build the remote activation command using configlet templates.

    With the rollback timer this is the ``try`` of the script copied to
    ``<script>.new``, and with *confirm* the ``confirm`` that follows it
    over a new connection.
    """
    if config.activation_cmd:
        return config.activation_cmd

    template_name = (
        'installer_commands_root'
        if config.user == 'root'
        else 'installer_commands_reg_user'
    )
    configlet = Configlet('linux24', template_name)
    configlet.collapse_empty_strings(True)
    configlet.set_variable('fwbprompt', '___INSTALL_DONE___')
    configlet.set_variable('fwdir', config.firewall_dir)

    # Remote script basename.
    if config.remote_script:
        script_name = Path(config.remote_script).name
    elif config.script_path:
        script_name = Path(config.script_path).name
    else:
        script_name = 'firewall.fw'

    configlet.set_variable('fwscript', script_name)
    configlet.set_variable('firewall_name', config.firewall_name)
    rollback = uses_rollback(config)
    configlet.set_variable('run', not rollback)
    configlet.set_variable('with_rollback', rollback and not confirm)
    configlet.set_variable('confirm', rollback and confirm)
    configlet.set_variable('rbtimeout', config.rollback_timeout)
    return configlet.expand().strip()


def build_job_list(config: InstallConfig) -> list[InstallJob]:
    """Build the list of install jobs from the manifest.

    If ``config.install_script`` is set, a single
    :data:`RUN_EXTERNAL_SCRIPT` job is created instead.
    """
    jobs: list[InstallJob] = []

    if config.install_script:
        jobs.append(
            InstallJob(
                JobType.RUN_EXTERNAL_SCRIPT,
                config.install_script,
                config.install_script_args,
            )
        )
        return jobs

    # With the rollback timer the script goes to <script>.new and becomes
    # the one the firewall boots with only once the activation is
    # confirmed, so a firewall that put the old ruleset back does not
    # load the new one again on its next reboot.
    staged = '.new' if uses_rollback(config) else ''

    # Read manifest from the compiled script.
    manifest = read_manifest(config.script_path)
    if not manifest:
        # Fallback: copy the script itself.
        local = config.script_path
        remote = config.remote_script or f'{config.firewall_dir}/{Path(local).name}'
        jobs.append(InstallJob(JobType.COPY_FILE, local, remote + staged))
    else:
        script_dir = str(Path(config.script_path).parent)
        script_name = Path(config.script_path).name
        for local_name, remote_name in manifest.items():
            local_path = str(Path(script_dir) / local_name)
            if local_name == script_name:
                remote_name += staged
            jobs.append(InstallJob(JobType.COPY_FILE, local_path, remote_name))

    # Optionally copy the .fwf database file.
    if config.copy_fwb and config.fwb_file:
        fwb_name = Path(config.fwb_file).name
        remote_fwb = f'{config.firewall_dir}/{fwb_name}'
        jobs.append(InstallJob(JobType.COPY_FILE, config.fwb_file, remote_fwb))

    # Activation command.
    cmd = get_activation_cmd(config)
    if cmd:
        jobs.append(InstallJob(JobType.ACTIVATE_POLICY, cmd, ''))
    if uses_rollback(config):
        jobs.append(
            InstallJob(
                JobType.CONFIRM_POLICY, get_activation_cmd(config, confirm=True), ''
            )
        )

    return jobs


# Prompts that indicate the remote side is asking for a password or
# passphrase.  Matching is case-sensitive and checked against the tail
# end of the accumulated process output (same approach as fwbuilder's
# SSHUnx state machine).
_PASSWORD_PROMPTS = (
    "'s password: ",
    'Enter passphrase for key ',
    'Password or swipe finger:',
    'Password: ',
    'Password:',
    '[sudo] password for ',
)


class FirewallInstaller(QObject):
    """Runs install jobs (SCP + SSH) via QProcess."""

    job_finished = Signal()
    job_failed = Signal(str)
    log_message = Signal(str)

    def __init__(self, config: InstallConfig, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._config = config
        self._jobs: list[InstallJob] = []
        self._process: QProcess | None = None
        self._output_buf = ''
        self._confirming = False
        self._askpass_dir: tempfile.TemporaryDirectory | None = None
        self._askpass_wrapper: Path | None = None
        self.job_finished.connect(self._cleanup_askpass)
        self.job_failed.connect(self._cleanup_askpass)

    def run_jobs(self) -> None:
        """Build the job list and start executing."""
        self._jobs = build_job_list(self._config)
        if not self._jobs:
            self.log_message.emit('<b>No install jobs to run.</b>')
            self.job_finished.emit()
            return
        self._run_next()

    def _ensure_askpass(self) -> Path | None:
        """Create the askpass wrapper on first use; None if unavailable."""
        if self._askpass_wrapper is None and self._askpass_dir is None:
            self._askpass_dir = tempfile.TemporaryDirectory(prefix='fwf-askpass-')
            try:
                self._askpass_wrapper = _ssh_askpass.write_wrapper(
                    Path(self._askpass_dir.name),
                )
            except OSError:
                logger.exception('Could not create the SSH askpass helper')
                self._askpass_wrapper = None
        return self._askpass_wrapper

    def _cleanup_askpass(self, *_args) -> None:
        if self._askpass_dir is not None:
            self._askpass_dir.cleanup()
        self._askpass_dir = None
        self._askpass_wrapper = None

    def _ssh_environment(self) -> QProcessEnvironment | None:
        """Environment that makes ssh/scp take the password from the
        askpass helper instead of a (possibly invisible) console."""
        if not self._config.password:
            return None
        wrapper = self._ensure_askpass()
        if wrapper is None:
            return None
        env = QProcessEnvironment.systemEnvironment()
        base = {'DISPLAY': env.value('DISPLAY')}
        for name, value in _ssh_askpass.environment(
            wrapper, self._config.password, base
        ).items():
            env.insert(name, value)
        return env

    def _batch_mode_args(self, user_args: str) -> list[str]:
        """On Windows, OpenSSH prompts on a console the user cannot see
        and would hang forever. Without a password, fail fast instead."""
        if not _IS_WINDOWS or self._config.password:
            return []
        if 'batchmode' in user_args.lower():
            return []
        return ['-o', 'BatchMode=yes']

    def _run_next(self) -> None:
        if not self._jobs:
            self.job_finished.emit()
            return

        job = self._jobs.pop(0)
        if job.job_type == JobType.COPY_FILE:
            self._copy_file(job.arg1, job.arg2)
        elif job.job_type == JobType.ACTIVATE_POLICY:
            self._activate_policy(job.arg1)
        elif job.job_type == JobType.CONFIRM_POLICY:
            self._confirm_policy(job.arg1)
        elif job.job_type == JobType.RUN_EXTERNAL_SCRIPT:
            self._run_external_script(job.arg1, job.arg2)

    def _copy_file(self, local: str, remote: str) -> None:
        self.log_message.emit(
            f'<b>Copying {_esc(Path(local).name)} -> {_esc(remote)}</b>'
        )
        args = self._pack_scp_args(local, remote)
        self._start_process(args[0], args[1:], env=self._ssh_environment())

    def _activate_policy(self, cmd: str) -> None:
        self.log_message.emit(
            f'<b>Activating policy on {_esc(self._config.mgmt_address)}</b>'
        )
        args = self._pack_ssh_args(cmd)
        self._start_process(args[0], args[1:], env=self._ssh_environment())

    def _confirm_policy(self, cmd: str) -> None:
        """Confirm the activation over a connection of its own.

        The session that activated the policy proves nothing about the
        new rules: connection tracking lets an established session
        through that a new one may no longer get.  So the confirmation
        opens a new TCP connection - no multiplexed channel of an
        existing one - and gives up well before the firewall's timer
        runs out.
        """
        self.log_message.emit(
            f'<b>Confirming the activation over a new connection to'
            f' {_esc(self._config.mgmt_address)}</b>'
        )
        self._confirming = True
        connect_timeout = max(5, self._config.rollback_timeout // 2)
        args = self._pack_ssh_args(
            cmd,
            extra=[
                '-o',
                'ControlMaster=no',
                '-o',
                'ControlPath=none',
                '-o',
                f'ConnectTimeout={connect_timeout}',
            ],
        )
        self._start_process(args[0], args[1:], env=self._ssh_environment())

    def _run_external_script(self, script: str, script_args: str) -> None:
        self.log_message.emit(f'<b>Running external script: {_esc(script)}</b>')
        args = script_args.split() if script_args else []
        self._start_process(script, args)

    def _start_process(
        self,
        program: str,
        args: list[str],
        env: QProcessEnvironment | None = None,
    ) -> None:
        self._process = QProcess(self)
        if env is not None:
            self._process.setProcessEnvironment(env)
            if not _IS_WINDOWS:
                # OpenSSH before 8.4 (RHEL 8 ships 8.0) ignores
                # SSH_ASKPASS_REQUIRE and asks on the terminal whenever
                # there is one, so a GUI started from a terminal hung on
                # a prompt nobody saw.  Without a controlling terminal it
                # takes the helper too.
                self._process.setUnixProcessParameters(
                    QProcess.UnixProcessFlag.CreateNewSession
                )
        self._process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self._process.readyReadStandardOutput.connect(self._on_output)
        self._process.finished.connect(self._on_finished)
        if self._config.verbose:
            self.log_message.emit(f'  $ {program} {" ".join(args)}')
        self._process.start(program, args)

    def _on_output(self) -> None:
        if self._process is None:
            return
        data = self._process.readAllStandardOutput().data()
        text = data.decode('utf-8', errors='replace').rstrip()
        if not text:
            return

        # Accumulate output for password prompt detection.
        self._output_buf += text

        if self._config.password and self._detect_password_prompt():
            self._process.write(
                QByteArray(
                    (self._config.password + '\n').encode('utf-8'),
                ),
            )
            self._output_buf = ''
            return

        indented = '\n'.join(f'    {line}' for line in text.splitlines())
        self.log_message.emit(
            f'<pre style="margin: 0; color: gray;'
            f' font-size: small;">{_esc(indented)}</pre>'
        )

    def _detect_password_prompt(self) -> bool:
        """Check whether the accumulated output contains a
        password or passphrase prompt."""
        return any(prompt in self._output_buf for prompt in _PASSWORD_PROMPTS)

    def _on_finished(self, exit_code: int, exit_status: QProcess.ExitStatus) -> None:
        output = self._output_buf
        confirming = self._confirming
        self._process = None
        self._output_buf = ''
        self._confirming = False
        if exit_code == 0 and exit_status == QProcess.ExitStatus.NormalExit:
            self._run_next()
            return
        message = f'Process exited with code {exit_code}'
        if confirming:
            message += (
                '. The activation could not be confirmed over a new'
                ' connection, so the firewall puts back the ruleset that was'
                f' running before, at the latest {self._config.rollback_timeout}'
                ' seconds after the activation, and keeps the script it'
                ' boots with.'
            )
        elif 'Host key verification failed' in output:
            message += (
                '. The host key of the firewall is not known yet: connect'
                ' once with ssh from a terminal, check and accept the key,'
                ' then install again.'
            )
        elif 'Permission denied' in output:
            message += '. The firewall rejected the user name or password.'
        self.job_failed.emit(message)

    def _pack_ssh_args(self, cmd: str, extra: list[str] | None = None) -> list[str]:
        """Build SSH command line arguments.

        Reads the SSH path and timeout from global preferences
        (``Preferences > Installer`` tab).  *extra* options go in front
        of the user's own, so that ssh, which takes the first value of an
        option, lets them win.
        """
        settings = QSettings()
        ssh_path = settings.value(
            'SSH/SSHPath',
            shutil.which('ssh') or 'ssh',
            type=str,
        )
        timeout = settings.value('SSH/SSHTimeout', 10, type=int)
        args = [
            ssh_path,
            '-o',
            f'ServerAliveInterval={timeout}',
            '-t',
            '-t',
        ]
        args.extend(extra or [])
        args.extend(self._batch_mode_args(self._config.ssh_args))
        if self._config.ssh_args:
            args.extend(self._config.ssh_args.split())
        args.extend(['-l', self._config.user, self._config.mgmt_address, cmd])
        return args

    def _pack_scp_args(self, local: str, remote: str) -> list[str]:
        """Build SCP command line arguments.

        Reads the SCP path and timeout from global preferences
        (``Preferences > Installer`` tab).  The ConnectTimeout for SCP
        is derived from the SSH timeout multiplied by 3 (matching
        fwbuilder behaviour with ``ServerAliveCountMax=3``).
        """
        settings = QSettings()
        scp_path = settings.value(
            'SSH/SCPPath',
            shutil.which('scp') or 'scp',
            type=str,
        )
        timeout = settings.value('SSH/SSHTimeout', 10, type=int)
        connect_timeout = timeout * 3 if timeout > 0 else 90
        args = [
            scp_path,
            '-o',
            f'ConnectTimeout={connect_timeout}',
        ]
        args.extend(self._batch_mode_args(self._config.scp_args))
        if self._config.scp_args:
            args.extend(self._config.scp_args.split())
        if self._config.quiet:
            args.append('-q')
        args.append(local)

        # Wrap IPv6 addresses in brackets for SCP.
        addr = self._config.mgmt_address
        if ':' in addr:
            addr = f'[{addr}]'
        args.append(f'{self._config.user}@{addr}:{remote}')
        return args

    def terminate(self) -> None:
        """Kill the running process."""
        if (
            self._process is not None
            and self._process.state() != QProcess.ProcessState.NotRunning
        ):
            self._process.kill()
            self._process.waitForFinished(3000)
        self._jobs.clear()
        self._cleanup_askpass()
