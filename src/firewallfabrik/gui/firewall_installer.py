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

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, auto
from pathlib import Path
from typing import NamedTuple

from PySide6.QtCore import QObject, QProcess, Signal

from firewallfabrik.driver._configlet import Configlet


class JobType(IntEnum):
    COPY_FILE = auto()
    ACTIVATE_POLICY = auto()
    RUN_EXTERNAL_SCRIPT = auto()


class InstallJob(NamedTuple):
    job_type: JobType
    arg1: str
    arg2: str


@dataclass
class InstallConfig:
    """Per-firewall installation configuration."""

    user: str = 'root'
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


def get_activation_cmd(config: InstallConfig) -> str:
    """Build the remote activation command using configlet templates."""
    if config.activation_cmd:
        return config.activation_cmd

    template_name = (
        'installer_commands_root'
        if config.user == 'root'
        else 'installer_commands_reg_user'
    )
    configlet = Configlet('linux24', template_name)
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
    configlet.set_variable('run', True)
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

    # Read manifest from the compiled script.
    manifest = read_manifest(config.script_path)
    if not manifest:
        # Fallback: copy the script itself.
        local = config.script_path
        remote = config.remote_script or f'{config.firewall_dir}/{Path(local).name}'
        jobs.append(InstallJob(JobType.COPY_FILE, local, remote))
    else:
        script_dir = str(Path(config.script_path).parent)
        for local_name, remote_name in manifest.items():
            local_path = str(Path(script_dir) / local_name)
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

    return jobs


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

    def run_jobs(self) -> None:
        """Build the job list and start executing."""
        self._jobs = build_job_list(self._config)
        if not self._jobs:
            self.log_message.emit('No install jobs to run.')
            self.job_finished.emit()
            return
        self._run_next()

    def _run_next(self) -> None:
        if not self._jobs:
            self.job_finished.emit()
            return

        job = self._jobs.pop(0)
        if job.job_type == JobType.COPY_FILE:
            self._copy_file(job.arg1, job.arg2)
        elif job.job_type == JobType.ACTIVATE_POLICY:
            self._activate_policy(job.arg1)
        elif job.job_type == JobType.RUN_EXTERNAL_SCRIPT:
            self._run_external_script(job.arg1, job.arg2)

    def _copy_file(self, local: str, remote: str) -> None:
        self.log_message.emit(f'Copying {Path(local).name} -> {remote}')
        args = self._pack_scp_args(local, remote)
        self._start_process(args[0], args[1:])

    def _activate_policy(self, cmd: str) -> None:
        self.log_message.emit(f'Activating policy on {self._config.mgmt_address}')
        args = self._pack_ssh_args(cmd)
        self._start_process(args[0], args[1:])

    def _run_external_script(self, script: str, script_args: str) -> None:
        self.log_message.emit(f'Running external script: {script}')
        args = script_args.split() if script_args else []
        self._start_process(script, args)

    def _start_process(self, program: str, args: list[str]) -> None:
        self._process = QProcess(self)
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
        if text:
            self.log_message.emit(text)

    def _on_finished(self, exit_code: int, exit_status: QProcess.ExitStatus) -> None:
        self._process = None
        if exit_code == 0 and exit_status == QProcess.ExitStatus.NormalExit:
            self._run_next()
        else:
            self.job_failed.emit(f'Process exited with code {exit_code}')

    def _pack_ssh_args(self, cmd: str) -> list[str]:
        """Build SSH command line arguments."""
        args = [
            'ssh',
            '-o',
            'ServerAliveInterval=30',
            '-t',
            '-t',
        ]
        if self._config.ssh_args:
            args.extend(self._config.ssh_args.split())
        args.extend(['-l', self._config.user, self._config.mgmt_address, cmd])
        return args

    def _pack_scp_args(self, local: str, remote: str) -> list[str]:
        """Build SCP command line arguments."""
        args = [
            'scp',
            '-o',
            'ConnectTimeout=90',
        ]
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
