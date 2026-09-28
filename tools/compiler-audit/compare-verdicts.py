#!/usr/bin/env python3
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

"""Do two compiles of the same firewall decide the same packets the same way?

Every other oracle here asks whether a ruleset is accepted, or what it says.
This one sends packets through it.  Compile the corpus with the old and the
new compiler, then:

    git worktree add /tmp/before HEAD~1
    PYTHONPATH=/tmp/before/src python tools/compiler-audit/compile-corpus.py /tmp/out-before
    python tools/compiler-audit/compile-corpus.py /tmp/out-after
    python tools/compiler-audit/compare-verdicts.py /tmp/out-before /tmp/out-after

For every nftables ruleset whose rules changed, the packets are built from
what the two rulesets name - their addresses, ports and interfaces, plus
an address and a port neither names - and each one is sent through a
sandbox holding the old ruleset and through one holding the new.  A packet
one of them lets through and the other stops is the report.  That is the
question a change that only rewrites rules - folding addresses into a set,
moving a rate limit, reordering - has to answer, and `compare-output.py`
cannot: it sees that the text changed, not whether a packet notices.

How a verdict is taken, and why it can be trusted:

* The sandbox is a private network namespace (`unshare -rnm`, no root).  The
  firewall is that namespace; every interface the rulesets name is a veth
  whose other end sits in a namespace of its own.  A packet is written
  byte by byte - source, destination, protocol, port - and sent from the
  neighbour behind its incoming interface (input, forward) or from the
  firewall itself (output).  It counts as let through when the firewall
  delivers it locally (a raw socket, which the kernel serves after the
  input hook) or when it appears on the wire of its outgoing interface.
* Every run is a fresh sandbox, so no connection tracked in one run makes
  a packet of the next look established.
* A run without any ruleset comes first.  A packet that does not arrive
  there is one the sandbox cannot deliver - a martian source, a
  broadcast - and is left out, instead of reading as "both rulesets drop
  it", which would pass whatever the rulesets do.  A sandbox that delivers
  nothing fails the whole comparison for the same reason.
* A packet the two runs disagree on is sent again, on its own, in a fresh
  sandbox for each ruleset, and reported only if they disagree again.  A
  rate limit spends its tokens on the packets before it, so a verdict in a
  batch depends on the order and the timing; alone it does not.

Only IPv4 is probed, and only the nftables output: the iptables output is
a shell script of many commands that would have to be replayed first.  A
ruleset the kernel refuses is reported and skipped - `load-nft.sh` is the
oracle for that.  Named sets the script fills after loading (address
tables, run-time DNS names, dynamic interfaces) stay empty on both sides.
"""

from __future__ import annotations

import argparse
import contextlib
import ipaddress
import json
import os
import random
import re
import shlex
import socket
import struct

# The sandbox is driven by ip, nft, nsenter and unshare; every call gets
# an argument list, never a shell.
import subprocess  # nosec B404
import sys
import tempfile
import time
from pathlib import Path

# The links between the firewall and its neighbours.  A range no corpus
# names, so it cannot collide with an address a rule matches on.
LINK_NET = ipaddress.ip_network('100.127.0.0/16')
# An address and a port no rule should name, so every rule also meets a
# packet it does not match.
STRANGER_ADDRS = ('100.126.0.9', '100.126.0.10')
STRANGER_PORT = 47113

HOOKS = ('input', 'forward', 'output')
PROTOCOLS = {'icmp': 1, 'tcp': 6, 'udp': 17}
ETH_P_IP = 0x0800
PACKET_OUTGOING = 4

RULESET_RE = re.compile(r"<<\s*'?NFT_RULES'?\n(.*?)^NFT_RULES$", re.M | re.S)
IPV4_RE = re.compile(r'(?<![\d.:])(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?(?![\d.:])')
PORT_RE = re.compile(r'\b[ds]port\s+(?:!=\s*)?(\{[^}]*\}|\S+)')
IFACE_RE = re.compile(r'\b(?:iifname|oifname|iif|oif)\s+(?:!=\s*)?(\{[^}]*\}|\S+)')


def ruleset(path: Path) -> str:
    """Return the ruleset the script loads, or '' when it has none."""
    match = RULESET_RE.search(path.read_text(errors='replace'))
    return match.group(1) if match else ''


def rules_only(text: str) -> list[str]:
    """The lines that decide something; comments and blank lines do not."""
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith('#')
    ]


# -- What to send -----------------------------------------------------------


def addresses(text: str) -> list[str]:
    """Every IPv4 address a rule names, one host out of every network."""
    found = set()
    for addr, prefix in IPV4_RE.findall(text):
        try:
            if prefix:
                net = ipaddress.ip_network(f'{addr}/{prefix}', strict=False)
                host = net.network_address + (1 if net.num_addresses > 2 else 0)
            else:
                host = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if (
            host.is_multicast
            or host.is_loopback
            or host.is_unspecified
            or host == ipaddress.ip_address('255.255.255.255')
            or host in LINK_NET
        ):
            continue
        found.add(str(host))
    return sorted(found, key=ipaddress.ip_address)


def ports(text: str) -> list[int]:
    """Every port a rule names, both ends of a range."""
    found = set()
    for value in PORT_RE.findall(text):
        for part in re.split(r'[\s,{}]+', value):
            for number in part.split('-'):
                if number.isdigit() and 0 < int(number) < 65536:
                    found.add(int(number))
    return sorted(found)


def interfaces(text: str) -> list[str]:
    """Every interface a rule names; a wildcard becomes one name it matches."""
    found = set()
    for value in IFACE_RE.findall(text):
        for part in re.split(r'[\s,{}]+', value):
            name = part.strip('"')
            if not name or name == 'lo' or not re.fullmatch(r'[\w.*-]+', name):
                continue
            name = name.replace('*', '0')
            if len(name) <= 15:
                found.add(name)
    return sorted(found) or ['eth0', 'eth1']


def make_probes(texts: list[str], limit: int, seed: str) -> list[dict]:
    """Draw up to *limit* distinct packets out of what the rulesets name."""
    text = '\n'.join(texts)
    addrs = [*addresses(text), *STRANGER_ADDRS]
    services = [('icmp', 0)]
    for port in [*ports(text), STRANGER_PORT]:
        services += [('tcp', port), ('udp', port)]
    ifaces = interfaces(text)

    rng = random.Random(seed)
    probes, seen = [], set()
    # Draw with replacement until enough distinct ones are found or the
    # space is exhausted; the product itself is too large to enumerate.
    for _ in range(limit * 20):
        if len(probes) >= limit:
            break
        hook = rng.choice(HOOKS)
        proto, port = rng.choice(services)
        key = (
            hook,
            '' if hook == 'output' else rng.choice(ifaces),
            '' if hook == 'input' else rng.choice(ifaces),
            rng.choice(addrs),
            rng.choice(addrs),
            proto,
            port,
        )
        if key[3] == key[4] or key in seen:
            continue
        seen.add(key)
        probes.append(
            dict(
                zip(
                    ('hook', 'iin', 'iout', 'src', 'dst', 'proto', 'dport'),
                    key,
                    strict=True,
                )
            )
        )
    for number, probe in enumerate(probes, start=1):
        probe['id'] = number
    return probes


def describe(probe: dict) -> str:
    via = {
        'input': f'{probe["iin"]} -> fw',
        'forward': f'{probe["iin"]} -> {probe["iout"]}',
        'output': f'fw -> {probe["iout"]}',
    }[probe['hook']]
    port = f':{probe["dport"]}' if probe['proto'] != 'icmp' else ''
    return (
        f'{probe["hook"]:7} {via:22} {probe["proto"]:4} '
        f'{probe["src"]} -> {probe["dst"]}{port}'
    )


# -- The sandbox (runs inside `unshare -rn`) --------------------------------


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack(f'!{len(data) // 2}H', data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def packet(probe: dict) -> bytes:
    """Build the IPv4 packet for *probe*, checksums and all.

    The transport checksum has to be right: conntrack checks it
    (nf_conntrack_checksum is on by default) and calls a packet with a bad
    one invalid, which a ruleset dropping invalid packets then drops for a
    reason that has nothing to do with the rule under test.
    """
    src, dst = socket.inet_aton(probe['src']), socket.inet_aton(probe['dst'])
    number = PROTOCOLS[probe['proto']]
    sport = 20000 + probe['id']
    if probe['proto'] == 'icmp':
        body = struct.pack('!BBHHH', 8, 0, 0, probe['id'], 1) + b'fwf'
        body = body[:2] + struct.pack('!H', checksum(body)) + body[4:]
    else:
        if probe['proto'] == 'tcp':
            # A SYN: the first packet of a connection, which is what a
            # rule matching `ct state new` or `tcp flags syn` waits for.
            body = struct.pack(
                '!HHIIBBHHH', sport, probe['dport'], 1, 0, 5 << 4, 0x02, 64240, 0, 0
            )
            offset = 16
        else:
            body = struct.pack('!HHHH', sport, probe['dport'], 8 + 3, 0) + b'fwf'
            offset = 6
        pseudo = src + dst + struct.pack('!BBH', 0, number, len(body))
        body = (
            body[:offset]
            + struct.pack('!H', checksum(pseudo + body))
            + body[offset + 2 :]
        )
    header = struct.pack(
        '!BBHHHBBH4s4s',
        0x45,
        0,
        20 + len(body),
        probe['id'],
        0,
        64,
        number,
        0,
        src,
        dst,
    )
    return header + body


def send(sender: socket.socket, probe: dict) -> None:
    # A packet the kernel will not even send is one the control run does
    # not deliver either, so it is left out there.
    with contextlib.suppress(OSError):
        sender.sendto(packet(probe), (probe['dst'], 0))


def drain(
    local: list[socket.socket],
    wire: dict[str, socket.socket],
    wanted: dict[int, dict],
    arrived: set[int],
) -> None:
    """Collect the probes that have arrived since the last call."""
    for sock in local:
        with contextlib.suppress(BlockingIOError):
            while True:
                data = sock.recv(65535)
                number = struct.unpack('!H', data[4:6])[0]
                if number in wanted and wanted[number]['hook'] == 'input':
                    arrived.add(number)
    for name, sock in wire.items():
        with contextlib.suppress(BlockingIOError):
            while True:
                data, address = sock.recvfrom(65535)
                if address[2] == PACKET_OUTGOING:
                    continue
                number = struct.unpack('!H', data[4:6])[0]
                probe = wanted.get(number)
                if probe and probe['hook'] != 'input' and probe['iout'] == name:
                    arrived.add(number)


def sh(command: str) -> str:
    """Run one command, split into words; no shell ever sees it.

    The interface names come out of a ruleset, and a name is spliced into
    these commands, so a shell would be one ruleset away from running
    something else.
    """
    # An argument list of fixed tools, found on the PATH like every other
    # tool in this directory.
    return subprocess.run(  # nosec B603 B607
        shlex.split(command), check=True, capture_output=True, text=True
    ).stdout


def write(path: str, value: str) -> None:
    Path(path).write_text(value)


class Sandbox:
    """The firewall namespace we run in, and one neighbour per interface."""

    def __init__(self, ifaces: list[str]) -> None:
        self.home = os.open('/proc/self/ns/net', os.O_RDONLY)
        self.neighbours: dict[str, subprocess.Popen] = {}
        self.link: dict[str, tuple[str, str]] = {}
        try:
            self._build(ifaces)
        except BaseException:
            self.close()
            raise

    def _build(self, ifaces: list[str]) -> None:
        sh('ip link set lo up')
        write('/proc/sys/net/ipv4/ip_forward', '1')
        for key in ('all', 'default'):
            write(f'/proc/sys/net/ipv4/conf/{key}/rp_filter', '0')
        hosts = LINK_NET.subnets(new_prefix=30)
        for name in ifaces:
            fw_addr, peer_addr = [str(h) for h in next(hosts).hosts()]
            # No inherited pipe: a neighbour holding the caller's stdout
            # open would keep the caller waiting for an end that never comes.
            proc = subprocess.Popen(  # nosec B603 B607
                ['unshare', '-n', 'sleep', 'infinity'],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.neighbours[name] = proc
            self.link[name] = (fw_addr, peer_addr)
            self._wait_for_namespace(proc.pid)
            sh(f'ip link add {name} type veth peer name peer0')
            sh(f'ip link set peer0 netns {proc.pid}')
            sh(f'ip addr add {fw_addr}/30 dev {name}')
            sh(f'ip link set {name} up')
            write(f'/proc/sys/net/ipv4/conf/{name}/rp_filter', '0')
            self.run_in(name, 'ip link set lo up')
            # A new namespace may start out forwarding, depending on the
            # host.  A neighbour that forwards sends every packet the
            # firewall routes back out of the interface it came in on
            # straight back, and the loop fills the receive buffers until
            # later packets are lost.
            self.run_in(name, 'sysctl -q -w net.ipv4.ip_forward=0')
            self.run_in(name, f'ip addr add {peer_addr}/30 dev peer0')
            self.run_in(name, 'ip link set peer0 up')
            self.run_in(name, f'ip route add default via {fw_addr}')
            # Static neighbours: no packet waits for, or is lost to, ARP.
            peer_mac = self.run_in(name, 'ip -br link show dev peer0').split()[2]
            fw_mac = sh(f'ip -br link show dev {name}').split()[2]
            sh(
                f'ip neigh replace {peer_addr} lladdr {peer_mac} dev {name} nud permanent'
            )
            self.run_in(
                name,
                f'ip neigh replace {fw_addr} lladdr {fw_mac} dev peer0 nud permanent',
            )

    @staticmethod
    def _wait_for_namespace(pid: int) -> None:
        own = Path('/proc/self/ns/net').stat().st_ino
        for _ in range(200):
            with contextlib.suppress(FileNotFoundError):
                if Path(f'/proc/{pid}/ns/net').stat().st_ino != own:
                    return
            time.sleep(0.01)
        raise RuntimeError('neighbour namespace did not come up')

    def run_in(self, name: str, command: str) -> str:
        # Not /sys: it stays mounted for the namespace it was mounted in, so
        # it names the host's interfaces whatever namespace reads it.
        pid = self.neighbours[name].pid
        return sh(f'nsenter --net=/proc/{pid}/ns/net {command}')

    @contextlib.contextmanager
    def inside(self, name: str):
        """Run the block in the neighbour's namespace; sockets stay there."""
        fd = os.open(f'/proc/{self.neighbours[name].pid}/ns/net', os.O_RDONLY)
        try:
            os.setns(fd, os.CLONE_NEWNET)
            yield
        finally:
            os.setns(self.home, os.CLONE_NEWNET)
            os.close(fd)

    def close(self) -> None:
        for proc in self.neighbours.values():
            proc.kill()
            proc.wait()


USER_RE = re.compile(r'meta sk(uid|gid) (?:!= )?([A-Za-z_][A-Za-z0-9._-]*)')


def known_accounts(rules: str) -> None:
    """Make every user and group the ruleset names exist here.

    nft looks a name after `meta skuid` / `meta skgid` up while it parses
    and refuses the whole ruleset when this machine has no such account
    (netfilter nftables src/meta.c), which says something about the
    machine and nothing about the rules.  The sandbox has a mount
    namespace of its own, so a copy of the account files with the missing
    names added is bound over the real ones for the length of the run -
    the way load-nft.sh does it.
    """
    wanted = {'uid': set(), 'gid': set()}
    for kind, name in USER_RE.findall(rules):
        wanted[kind].add(name)
    number = 60000
    for kind, path in (('uid', '/etc/passwd'), ('gid', '/etc/group')):
        lines = Path(path).read_text().splitlines()
        have = {line.split(':', 1)[0] for line in lines}
        for name in sorted(wanted[kind] - have):
            if kind == 'uid':
                lines.append(f'{name}:x:{number}:{number}::/nonexistent:/sbin/nologin')
            else:
                lines.append(f'{name}:x:{number}:')
            number += 1
        if len(lines) > len(have):
            # Kept until the sandbox exits; the bind mount goes with it.
            with tempfile.NamedTemporaryFile(
                'w', delete=False, suffix='.accounts'
            ) as copy:
                copy.write('\n'.join(lines) + '\n')
            sh(f'mount --bind {copy.name} {path}')


def run_sandbox(rules: str | None, probes: list[dict]) -> dict:
    """Send *probes* through *rules* (None: no ruleset); return what arrived."""
    ifaces = sorted(({p['iin'] for p in probes} | {p['iout'] for p in probes}) - {''})
    box = Sandbox(ifaces)
    try:
        if rules is not None:
            known_accounts(rules)
            with tempfile.NamedTemporaryFile('w', suffix='.nft') as handle:
                handle.write(rules)
                handle.flush()
                result = subprocess.run(  # nosec B603 B607
                    ['nft', '--file', handle.name], capture_output=True, text=True
                )
            if result.returncode:
                # nft prints the offending line and a caret under it; the
                # sentence saying what is wrong is the one worth keeping.
                reasons = [
                    line.strip()
                    for line in result.stderr.splitlines()
                    if 'Error:' in line
                ]
                return {'error': reasons[:1] or result.stderr.strip().splitlines()[-1:]}

        # Receivers: raw sockets see what the firewall delivers to itself,
        # after its input hook; a packet socket on each neighbour's end of
        # the wire sees what the firewall sent out of that interface.
        local = [
            socket.socket(socket.AF_INET, socket.SOCK_RAW, number)
            for number in PROTOCOLS.values()
        ]
        wire, senders = {}, {}
        for name in ifaces:
            with box.inside(name):
                wire[name] = socket.socket(
                    socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_IP)
                )
                senders[name] = socket.socket(
                    socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW
                )
        own_sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        for sock in [*local, *wire.values()]:
            sock.setblocking(False)

        # Routing only has to be right for the group being sent, so the
        # packets go out in groups that share it.
        groups: dict[tuple, list[dict]] = {}
        for probe in probes:
            groups.setdefault((probe['hook'], probe['iin'], probe['iout']), []).append(
                probe
            )
        wanted = {p['id']: p for p in probes}
        arrived: set[int] = set()
        for (hook, iin, iout), group in sorted(groups.items()):
            if hook == 'input':
                # One at a time: the destination has to be an address of
                # the firewall, and a source that is one too is a martian
                # the kernel drops before any rule sees it.
                for probe in group:
                    sh(f'ip addr add {probe["dst"]}/32 dev lo')
                    send(senders[iin], probe)
                    time.sleep(0.01)
                    drain(local, wire, wanted, arrived)
                    sh(f'ip addr del {probe["dst"]}/32 dev lo')
                continue
            sh(f'ip route replace default via {box.link[iout][1]} dev {iout} table 100')
            source = f'iif {iin}' if hook == 'forward' else 'iif lo'
            sh(f'ip rule add {source} lookup 100 priority 100')
            for probe in group:
                send(own_sender if hook == 'output' else senders[iin], probe)
            time.sleep(0.05)
            drain(local, wire, wanted, arrived)
            sh('ip rule del priority 100')
        time.sleep(0.1)
        drain(local, wire, wanted, arrived)
        return {'arrived': sorted(arrived)}
    finally:
        box.close()


# -- Driving it -------------------------------------------------------------


def sandbox(rules: str | None, probes: list[dict]) -> dict:
    """Run one sandbox in a private namespace of its own."""
    with tempfile.NamedTemporaryFile('w', suffix='.json') as handle:
        json.dump({'rules': rules, 'probes': probes}, handle)
        handle.flush()
        try:
            result = subprocess.run(  # nosec B603 B607
                ['unshare', '-rnm', sys.executable, __file__, '--sandbox', handle.name],
                capture_output=True,
                text=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            return {'error': ['the sandbox did not finish within five minutes']}
    if result.returncode:
        return {'error': result.stderr.strip().splitlines()[-3:]}
    return json.loads(result.stdout)


def compare(before_path: Path, after_path: Path, limit: int) -> tuple[str, list[str]]:
    """Return a status word and the report lines for one firewall."""
    before, after = ruleset(before_path), ruleset(after_path)
    if not before or not after:
        return 'skipped', []
    if rules_only(before) == rules_only(after):
        return 'unchanged', []

    probes = make_probes([before, after], limit, str(after_path))
    control = sandbox(None, probes)
    if 'error' in control:
        return 'broken', [f'sandbox failed: {control["error"]}']
    drawn = len(probes)
    deliverable = set(control['arrived'])
    if not deliverable:
        return 'broken', ['the sandbox delivered none of the packets without a ruleset']
    probes = [p for p in probes if p['id'] in deliverable]

    runs = {}
    for label, text in (('before', before), ('after', after)):
        runs[label] = sandbox(text, probes)
        if 'error' in runs[label]:
            return 'refused', [
                f'{label}: the kernel refused the ruleset: {runs[label]["error"]}'
            ]

    lines = [
        f'{drawn} packets drawn, {len(probes)} of them delivered without a ruleset'
    ]
    passed_before, passed_after = (
        set(runs['before']['arrived']),
        set(runs['after']['arrived']),
    )
    differ = [
        p for p in probes if (p['id'] in passed_before) != (p['id'] in passed_after)
    ]
    confirmed = []
    for probe in differ:
        alone = [dict(probe, id=1)]
        again_before = 1 in sandbox(before, alone).get('arrived', [])
        again_after = 1 in sandbox(after, alone).get('arrived', [])
        if again_before != again_after:
            confirmed.append((probe, again_before, again_after))
    if not confirmed:
        return 'same', lines
    word = {True: 'passes', False: 'stopped'}
    for probe, was, now in confirmed:
        lines.append(f'{describe(probe)}   before: {word[was]}, after: {word[now]}')
    return 'differ', lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('before', type=Path, nargs='?')
    parser.add_argument('after', type=Path, nargs='?')
    parser.add_argument(
        '--probes', type=int, default=300, help='packets per firewall (default 300)'
    )
    parser.add_argument('--only', default='', help='compare only paths containing this')
    parser.add_argument('--sandbox', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.sandbox:
        job = json.loads(args.sandbox.read_text())
        print(json.dumps(run_sandbox(job['rules'], job['probes'])))
        return 0
    if not args.before or not args.after:
        parser.error('two compiled trees are needed')

    counts: dict[str, int] = {}
    for after_path in sorted((args.after / 'nft').rglob('*.fw')):
        relative = after_path.relative_to(args.after)
        before_path = args.before / relative
        if args.only not in str(relative) or not before_path.exists():
            continue
        status, lines = compare(before_path, after_path, args.probes)
        counts[status] = counts.get(status, 0) + 1
        if status in ('differ', 'broken', 'refused'):
            print(f'=== {relative}')
            for line in lines:
                print(f'  {line}')

    print('---')
    compared = counts.get('same', 0) + counts.get('differ', 0)
    print(
        f'{compared} changed rulesets compared, {counts.get("differ", 0)} decide a '
        f'packet differently; {counts.get("unchanged", 0)} unchanged, '
        f'{counts.get("refused", 0)} refused, {counts.get("broken", 0)} sandbox failures'
    )
    return 1 if counts.get('differ') or counts.get('broken') else 0


if __name__ == '__main__':
    sys.exit(main())
