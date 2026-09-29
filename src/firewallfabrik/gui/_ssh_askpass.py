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

"""SSH_ASKPASS helper used by the firewall installer.

OpenSSH never reads a password from stdin; it asks on the terminal,
or runs the program named in ``SSH_ASKPASS``. The installer points
``SSH_ASKPASS`` at a small wrapper that runs this script, and passes
the password in the ``FWF_SSH_ASKPASS_SECRET`` environment variable of
the ssh/scp process only.

OpenSSH passes the prompt as the first argument. The password is only
answered to password and passphrase prompts. Anything else, such as the
"Are you sure you want to continue connecting (yes/no)?" host key
question, is refused with a non-zero exit status: OpenSSH then aborts
with a clear error instead of hanging or accepting an unknown host key.

This file runs as a standalone script and must not import anything
from firewallfabrik. The installer and the version lookup import
``SECRET_ENV`` and ``write_wrapper()`` from it.
"""

import os
import shlex
import sys
from pathlib import Path

SECRET_ENV = 'FWF_SSH_ASKPASS_SECRET'  # nosec B105 - a variable name

_ANSWERED_PROMPTS = (
    'passphrase',
    'password',
)


_IS_WINDOWS = os.name == 'nt'


def _python() -> str | None:
    """A console Python interpreter to run this script, or None when
    running from a frozen build without one."""
    if getattr(sys, 'frozen', False) or not sys.executable:
        return None
    exe = Path(sys.executable)
    # pythonw.exe has no usable stdout; prefer python.exe next to it.
    if exe.name.lower() == 'pythonw.exe':
        console = exe.with_name('python.exe')
        if console.exists():
            exe = console
    return str(exe)


def write_wrapper(directory: Path) -> Path | None:
    """Write an executable wrapper that runs this script.

    ``SSH_ASKPASS`` must name a single program without arguments, so a
    batch file (Windows) or shell script (everywhere else) calls this
    script with the interpreter that runs FirewallFabrik. Returns the
    wrapper path, or None if no interpreter is available.
    """
    python = _python()
    if python is None:
        return None
    script = Path(__file__).resolve()
    if _IS_WINDOWS:
        wrapper = Path(directory) / 'fwf-askpass.cmd'
        wrapper.write_text(
            f'@echo off\r\n"{python}" "{script}" %*\r\n',
            encoding='utf-8',
        )
    else:
        wrapper = Path(directory) / 'fwf-askpass.sh'
        wrapper.write_text(
            f'#!/bin/sh\nexec {shlex.quote(python)} {shlex.quote(str(script))} "$@"\n',
            encoding='utf-8',
        )
        wrapper.chmod(0o700)
    return wrapper


def environment(wrapper: Path, secret: str, base: dict[str, str]) -> dict[str, str]:
    """The variables that make ssh/scp ask *wrapper* for *secret*."""
    return {
        # OpenSSH >= 8.4 uses SSH_ASKPASS whenever this is set to force,
        # even with a terminal or console attached.
        'SSH_ASKPASS_REQUIRE': 'force',
        'SSH_ASKPASS': str(wrapper),
        # Older OpenSSH only uses SSH_ASKPASS when DISPLAY is set and
        # there is no terminal.
        'DISPLAY': base.get('DISPLAY') or ':0',
        SECRET_ENV: secret,
    }


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    prompt = ' '.join(argv).lower()
    secret = os.environ.get(SECRET_ENV)
    if secret is None or not any(p in prompt for p in _ANSWERED_PROMPTS):
        return 1
    os.write(1, (secret + '\n').encode('utf-8'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
