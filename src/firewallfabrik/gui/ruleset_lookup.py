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

"""Read the running ruleset of a firewall over SSH, for the import.

It logs in the way "Lookup Version ..." does (``version_lookup``) and
runs commands that read and change nothing: ``nft -j list ruleset``,
``iptables-save``, ``ip6tables-save``, ``ip -j addr`` and ``ip -j route``,
plus what the version lookup asks.  Listing a ruleset needs
CAP_NET_ADMIN, so a user other than root runs them through ``sudo -n``,
which fails instead of asking for a password nobody could type.

Nothing here needs Qt.
"""

from __future__ import annotations

import dataclasses

from firewallfabrik.gui import version_lookup

_REMOTE = (
    'PATH="$PATH:/usr/sbin:/sbin"; S=""; '
    '[ "$(id -u)" = 0 ] || S="sudo -n"; '
    'echo "@@RS_SUDO"; $S true 2>&1 && echo ok; '
    'echo "@@RS_NFT"; $S nft -j list ruleset 2>/dev/null; '
    'echo "@@RS_IPT4"; $S iptables-save 2>/dev/null; '
    'echo "@@RS_IPT6"; $S ip6tables-save 2>/dev/null; '
    'echo "@@RS_ADDR"; ip -j addr 2>/dev/null; '
    # Without -4 or -6, "table all" lists both families at once.
    'echo "@@RS_ROUTE4"; ip -4 -j route show table all 2>/dev/null; '
    'echo "@@RS_ROUTE6"; ip -6 -j route show table all 2>/dev/null; '
    'echo "@@RS_HOST"; hostname 2>/dev/null; '
) + version_lookup._REMOTE


@dataclasses.dataclass
class RemoteRuleset:
    """What the firewall printed."""

    nft_json: str = ''
    iptables_save: str = ''
    ip6tables_save: str = ''
    ip_addr_json: str = ''
    ip_route4_json: str = ''
    ip_route6_json: str = ''
    hostname: str = ''
    lookup: version_lookup.Lookup | None = None


class NotPermitted(version_lookup.LookupFailed):
    """The login works, but the user may not read the ruleset."""


def parse(output: str) -> RemoteRuleset:
    sections: dict[str, list[str]] = {}
    current = None
    for line in output.splitlines():
        if line.startswith('@@RS_'):
            current = line[5:].strip()
            sections[current] = []
        elif line.startswith('@@'):
            current = None
        elif current is not None:
            sections[current].append(line)
    if 'ok' not in sections.get('SUDO', []):
        raise NotPermitted(
            'the user may not read the ruleset: log in as root, or give the user '
            'sudo without a password for nft, iptables-save and ip6tables-save'
        )
    return RemoteRuleset(
        nft_json='\n'.join(sections.get('NFT', [])).strip(),
        iptables_save='\n'.join(sections.get('IPT4', [])),
        ip6tables_save='\n'.join(sections.get('IPT6', [])),
        ip_addr_json='\n'.join(sections.get('ADDR', [])).strip(),
        ip_route4_json='\n'.join(sections.get('ROUTE4', [])).strip(),
        ip_route6_json='\n'.join(sections.get('ROUTE6', [])).strip(),
        hostname='\n'.join(sections.get('HOST', [])).strip(),
        lookup=version_lookup.parse(output),
    )


# The empty default means "no password given, use the key or the agent".
def run(  # nosec B107
    address: str,
    user: str,
    extra_args: str = '',
    password: str = '',
    ssh_path: str = '',
    timeout: int = 10,
) -> RemoteRuleset:
    """Read the ruleset of the firewall at *address*."""
    return parse(
        version_lookup.run_remote(
            address, user, _REMOTE, extra_args, password, ssh_path, timeout
        )
    )
