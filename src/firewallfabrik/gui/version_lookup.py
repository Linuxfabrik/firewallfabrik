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

"""Ask a firewall which packet filter releases it runs.

The "Lookup Version ..." button of the firewall panel logs in the way the
installer does - the management address, the user and the ssh arguments
of the firewall's installer settings - and runs commands that read and
change nothing, as that user: `nft --version`, `iptables --version`,
`uname -r` and /etc/os-release.  The answer picks the entry of the release
list (`firewallfabrik.platforms._versions.entry_for`).

Nothing here needs Qt, so the lookup can be run and tested on its own.
"""

from __future__ import annotations

import dataclasses
import os
import re
import shlex
import shutil
import subprocess  # nosec B404
import tempfile
from pathlib import Path

from firewallfabrik.gui import _ssh_askpass
from firewallfabrik.platforms import _versions

# One command, so the machine is asked once.  /usr/sbin is not on an
# ordinary user's PATH on every distribution, and both tools print their
# release without root.  The markers keep the answers apart whatever a
# login banner or a missing tool prints.
_REMOTE = (
    'PATH="$PATH:/usr/sbin:/sbin"; '
    'echo "@@NFT"; nft --version 2>/dev/null; '
    'echo "@@IPT"; iptables --version 2>/dev/null; '
    'echo "@@KERNEL"; uname -r; '
    'echo "@@OS"; cat /etc/os-release 2>/dev/null; '
    'echo "@@END"'
)

_NFT_RE = re.compile(r'nftables v(\d+(?:\.\d+)+)')
_IPT_RE = re.compile(r'iptables v(\d+(?:\.\d+)+)(?: \(([a-z_]+)\))?')


@dataclasses.dataclass
class Lookup:
    """What the firewall answered, and the entries that fit it."""

    nftables: str = ''
    iptables: str = ''
    iptables_backend: str = ''
    kernel: str = ''
    os_release: dict[str, str] = dataclasses.field(default_factory=dict)

    @property
    def distribution(self) -> str:
        return self.os_release.get('PRETTY_NAME', '') or self.os_release.get('NAME', '')

    def entry(self, platform: str) -> str:
        release = self.nftables if platform == 'nftables' else self.iptables
        return _versions.entry_for(platform, release, self.os_release, self.kernel)


class LookupFailed(Exception):
    """The firewall could not be asked; the message says why."""


class AuthenticationRequired(LookupFailed):
    """The login needs a password, which was not given."""


def resolve_mgmt_address(fw):
    """Return the management address for a firewall, the installer's.

    Checks ``fw.options['altAddress']`` first, then scans interfaces
    for one flagged as management and returns its first IPv4 address,
    or its first IPv6 address when it has none.  Firewall Builder
    (``Host::getManagementAddress``) takes IPv4 only; the IPv6 fallback
    is FirewallFabrik's, so an IPv6-only firewall can be reached too.
    """
    options = fw.options or {}
    alt = options.get('altAddress', '')
    if alt:
        return alt
    for iface in fw.interfaces:
        iface_data = iface.data or {}
        if str(iface_data.get('management', '')).lower() not in ('true', '1'):
            continue
        # The interface also holds its MAC address (PhysAddress), which
        # ssh cannot connect to.
        for addr_type in ('IPv4', 'IPv6'):
            for addr in iface.addresses:
                if addr.type == addr_type and addr.get_address():
                    return addr.get_address()
    return ''


def login(fw, ssh_path: str = '', timeout: int = 10) -> dict:
    """The keyword arguments of :func:`run` for firewall *fw*.

    The installer settings of the firewall name the user and the ssh
    arguments; *ssh_path* and *timeout* are the SSH preferences.
    """
    options = fw.options or {}
    return {
        'address': resolve_mgmt_address(fw),
        'user': options.get('admUser', '') or 'root',
        'extra_args': options.get('sshArgs', ''),
        'ssh_path': ssh_path,
        'timeout': timeout or 10,
    }


def parse(output: str) -> Lookup:
    """Read the answer of the remote command."""
    sections: dict[str, list[str]] = {}
    current = None
    for line in output.splitlines():
        if line.startswith('@@'):
            current = line[2:].strip()
            sections[current] = []
        elif current is not None:
            sections[current].append(line)
    if 'END' not in sections:
        raise LookupFailed('the firewall did not answer the whole question')
    result = Lookup()
    nft = _NFT_RE.search('\n'.join(sections.get('NFT', [])))
    if nft:
        result.nftables = nft.group(1)
    ipt = _IPT_RE.search('\n'.join(sections.get('IPT', [])))
    if ipt:
        result.iptables = ipt.group(1)
        result.iptables_backend = ipt.group(2) or ''
    result.kernel = ' '.join(sections.get('KERNEL', [])).strip()
    for line in sections.get('OS', []):
        key, sep, value = line.partition('=')
        if sep:
            result.os_release[key.strip()] = value.strip().strip('"')
    return result


def ssh_args(
    address: str,
    user: str,
    extra_args: str,
    ssh_path: str = '',
    timeout: int = 10,
    remote: str = _REMOTE,
) -> list[str]:
    """The ssh command line, the way the installer builds it."""
    args = [
        ssh_path or shutil.which('ssh') or 'ssh',
        '-o',
        f'ConnectTimeout={timeout}',
    ]
    if extra_args:
        args.extend(shlex.split(extra_args))
    args.extend(['-l', user, address, remote])
    return args


# The empty default means "no password given, use the key or the agent".
def run(  # nosec B107
    address: str,
    user: str,
    extra_args: str = '',
    password: str = '',
    ssh_path: str = '',
    timeout: int = 10,
) -> Lookup:
    """Ask the firewall at *address*; raise LookupFailed on failure.

    Without a password the login must work non-interactively (a key or
    the ssh-agent), and a login that wants one raises
    AuthenticationRequired.  With one, ssh reads it through SSH_ASKPASS
    from a helper (see ``_ssh_askpass``) that prints an environment
    variable, so it appears neither on a command line nor in a file.
    """
    return parse(
        run_remote(address, user, _REMOTE, extra_args, password, ssh_path, timeout)
    )


# The empty default means "no password given, use the key or the agent".
def run_remote(  # nosec B107
    address: str,
    user: str,
    remote: str,
    extra_args: str = '',
    password: str = '',
    ssh_path: str = '',
    timeout: int = 10,
) -> str:
    """Run *remote* on the firewall at *address* and return what it printed.

    The login works the way :func:`run` describes; *remote* is a fixed
    command line of the caller, never something read from the firewall
    object.
    """
    if not address:
        raise LookupFailed(
            'the firewall has no management address: set "Alternative '
            'address" in its installer settings or mark an interface as '
            'management interface'
        )
    args = ssh_args(address, user, extra_args, ssh_path, timeout, remote)
    env = dict(os.environ)
    helper_dir = None
    if password:
        helper_dir = tempfile.TemporaryDirectory(prefix='fwf-askpass-')
        wrapper = _ssh_askpass.write_wrapper(Path(helper_dir.name))
        if wrapper is not None:
            env.update(_ssh_askpass.environment(wrapper, password, env))
        args[1:1] = ['-o', 'NumberOfPasswordPrompts=1']
    else:
        args[1:1] = ['-o', 'BatchMode=yes']
    try:
        # A fixed argument list; the address and the user come from the
        # firewall object and go in as arguments, never through a shell.
        proc = subprocess.run(  # nosec B603
            args,
            capture_output=True,
            text=True,
            timeout=timeout * 3,
            env=env,
            stdin=subprocess.DEVNULL,
            check=False,
            # Without a controlling terminal OpenSSH before 8.4, which
            # ignores SSH_ASKPASS_REQUIRE, takes the password from the
            # helper as well instead of asking on the terminal.
            start_new_session=os.name != 'nt',
        )
    except subprocess.TimeoutExpired as exc:
        raise LookupFailed(f'no answer from {address} within {timeout * 3}s') from exc
    except OSError as exc:
        raise LookupFailed(f'ssh could not be started: {exc}') from exc
    finally:
        if helper_dir is not None:
            helper_dir.cleanup()
    if proc.returncode == 255:
        message = proc.stderr.strip().splitlines()[-1:] or ['ssh failed']
        if 'Permission denied' in message[0] and not password:
            raise AuthenticationRequired(message[0])
        raise LookupFailed(message[0])
    return proc.stdout
