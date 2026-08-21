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

"""Facts about the netfilter hooks that both backends have to respect."""

from __future__ import annotations

import ipaddress
import re
import uuid

from firewallfabrik.compiler._combined_address import CombinedAddress
from firewallfabrik.core._options import option_is_true
from firewallfabrik.core.objects import (
    Host,
    Interface,
    PhysAddress,
    TagService,
    TCPUDPService,
)

# A packet only carries the device it goes out on once the routing decision
# is made, so the PRE_ROUTING and LOCAL_IN hooks cannot match an outgoing
# interface: the NF_HOOK calls in net/ipv4/ip_input.c pass NULL for it.
NO_OUTBOUND_DEVICE_CHAINS = frozenset({'input', 'prerouting'})

# A locally generated packet has no incoming device at all, so LOCAL_OUT
# cannot match one either (net/ipv4/ip_output.c:__ip_local_out and
# net/ipv6/ip6_output.c both enter the hook with NULL).
#
# POST_ROUTING is the exception, and it did not use to be: since kernel
# commit 28f8bfd1ac94 "netfilter: Support iif matches in POSTROUTING",
# first in v5.5, `ip_output()` and `ip6_output()` enter the hook with
# `skb->dev`, which for a routed packet is the device it came in on.  Its
# commit message names the consequence: "iptables (both legacy and nft)
# reject rules with input interface match from being added to POSTROUTING
# chains, but nftables allows this".  So whether a rule can match there is
# a question about the back end and not about the packet, which is what
# the *iif_in_postrouting* argument below answers.
NO_INBOUND_DEVICE_CHAINS = frozenset({'output'})


def tsrv_translation(osrv, tsrv) -> tuple[bool, bool]:
    """Report whether the translated service changes the src or dst port.

    Returns ``(translates_src_port, translates_dst_port)``.  A translated
    service that repeats the port of the original service translates
    nothing.  Mirrors ``NATCompiler::classifyNATRule``.
    """
    if not isinstance(osrv, TCPUDPService) or not isinstance(tsrv, TCPUDPService):
        return (False, False)

    src = (tsrv.src_range_start or 0) != 0 and (tsrv.dst_range_start or 0) == 0
    dst = (tsrv.src_range_start or 0) == 0 and (tsrv.dst_range_start or 0) != 0

    if dst and (
        (osrv.dst_range_start or 0) == (tsrv.dst_range_start or 0)
        and (osrv.dst_range_end or 0) == (tsrv.dst_range_end or 0)
    ):
        dst = False
    if src and (
        (osrv.src_range_start or 0) == (tsrv.src_range_start or 0)
        and (osrv.src_range_end or 0) == (tsrv.src_range_end or 0)
    ):
        src = False

    return (src, dst)


def destination_port_half(tsrv):
    """Return the destination-port half of a translated service.

    An SDNAT rule becomes a destination translation followed by a source
    translation, and the second one has to match what the first one left
    behind.  Where the translated service changes *both* ports, matching on
    it whole asks for the translated source port as well - a port the first
    rule never wrote, because a destination translation cannot change it.
    The rule then matches nothing and the source is never translated.
    fwbuilder builds a service carrying the destination half alone for that
    match (``NATCompiler_ipt::splitSDNATRule``, the ``_dport`` service).

    Returns *tsrv* itself when it translates the destination port only, so
    the caller can use the answer unconditionally.
    """
    if (tsrv.src_range_start or 0) == 0:
        return tsrv

    half = type(tsrv)()
    half.id = uuid.uuid4()
    half.name = f'{tsrv.name}_dport'
    half.dst_range_start = tsrv.dst_range_start
    half.dst_range_end = tsrv.dst_range_end
    half.named_protocols = tsrv.named_protocols
    return half


def interface_direction_problem(
    chain: str, inbound: bool, iif_in_postrouting: bool = False
) -> str:
    """Return why *chain* cannot match this interface, or an empty string.

    *chain* is the built-in chain the rule ends up in, in either spelling
    (iptables writes ``POSTROUTING``, nftables ``postrouting``).  A
    user-defined chain is never checked: which hook reaches it is decided
    by the rule that jumps to it.

    *iif_in_postrouting* says whether the caller can write a match on the
    incoming device into the postrouting chain.  nftables always can (see
    above); iptables refuses ``-i`` there outright ("Can't use
    --in-interface with POSTROUTING", netfilter iptables/xshared.c:
    ``do_parse`` calls ``option_test_and_reject``, for every table) but
    takes ``-m physdev --physdev-in``, which is what a bridge port is
    written as anyway.
    """
    name = chain.lower() if chain else ''
    if inbound and name == 'postrouting' and not iif_in_postrouting:
        return (
            'iptables refuses that in the POSTROUTING chain, where only a '
            'bridge port can be matched'
        )
    if inbound and name in NO_INBOUND_DEVICE_CHAINS:
        return f'a packet in the {chain} chain has no incoming interface'
    if not inbound and name in NO_OUTBOUND_DEVICE_CHAINS:
        return f'a packet in the {chain} chain has no outgoing interface yet'
    return ''


def nat_interface_problem(
    chain: str,
    has_itf_inb: bool,
    has_itf_outb: bool,
    iif_in_postrouting: bool = False,
) -> str:
    """Return why *chain* cannot match a NAT rule's interfaces, or ``''``.

    A NAT rule names its interfaces in two elements of its own instead of
    carrying a direction, so it can name both at once.  Which chain it ends
    up in follows from what it translates: a source translation runs in
    postrouting, a destination translation in prerouting, and a locally
    generated one in output.  The same hook facts as in
    :func:`interface_direction_problem` then rule one of the two elements
    out.
    """
    if has_itf_inb:
        problem = interface_direction_problem(
            chain, inbound=True, iif_in_postrouting=iif_in_postrouting
        )
        if problem:
            return f'matches on the incoming interface but {problem}'
    if has_itf_outb:
        problem = interface_direction_problem(chain, inbound=False)
        if problem:
            return f'matches on the outgoing interface but {problem}'
    return ''


# The longest interface name either tool takes.  IFNAMSIZ is 16 and holds
# the terminator, so 15 characters fit.  iptables checks it itself
# ("interface name `%s' must be shorter than IFNAMSIZ (%i)",
# netfilter iptables libxtables/xtables.c: xtables_parse_interface) and
# nftables answers "String exceeds maximum length of 16"; the kernel
# cannot carry a longer name either.
MAX_INTERFACE_NAME_LENGTH = 15


def check_interface_name(compiler, name: str, already_reported: set[str]) -> bool:
    """Whether a rule can match on *name*, reporting the reason once.

    Such a name cannot come from a running system - the kernel enforces
    the same limit - but it can come from an imported or hand-edited data
    file.  iptables then stops the activation script and nftables refuses
    the whole ruleset, so the rule is left out rather than emitted without
    its interface match, which would widen it to every interface.
    """
    if not name or len(name.rstrip('*+')) <= MAX_INTERFACE_NAME_LENGTH:
        return True
    if getattr(compiler, 'muted_now', False):
        # Marking the name as reported now would swallow the message: the
        # dedup pass renders every rule with messages discarded.
        return False
    if name not in already_reported:
        already_reported.add(name)
        compiler.error(
            f'Interface name "{name}" is longer than the '
            f'{MAX_INTERFACE_NAME_LENGTH} characters iptables and nftables can '
            'carry; the rules matching on it are left out. Rename the '
            'interface.',
        )
    return False


# The flags of an IPService that name an IPv4 header option.  "any_opt"
# stands for "carries any option at all".
_IP_OPTION_FLAGS = ('any_opt', 'lsrr', 'rr', 'rtralt', 'ssrr', 'ts')


def has_ip_options(data: dict) -> bool:
    """Whether an IPService asks for an IPv4 header option.

    The IPv4 option field has no IPv6 counterpart: IPv6 moved what used to
    be options into extension headers, and neither iptables nor nftables
    offers a match for the old field there.  A rule whose service names one
    therefore cannot be compiled for IPv6, and dropping just the condition
    would widen the rule to every packet - which is why the callers report
    it and leave the rule out of the IPv6 ruleset.
    """
    return any(option_is_true(data.get(flag)) for flag in _IP_OPTION_FLAGS)


# Spellings Firewall Builder 2.1 stored for the key a rate limit counts
# by, mapped to the ones netfilter takes.  hashlimit knows only the short
# ones (extensions/libxt_hashlimit.c, parse_mode) and answers "Bad value
# for --hashlimit-mode" for anything else; dstlimit takes `destport` only
# inside its compound words and never `destip` at all.
_HASHLIMIT_MODE_ALIASES = {
    'destip': 'dstip',
    'destport': 'dstport',
    'sourceip': 'srcip',
    'sourceport': 'srcport',
}


# A traffic class is a tc handle, two hexadecimal numbers separated by a
# colon.  The CLASSIFY target reads it with sscanf("%x:%x") and answers
# anything else with `Bad class value` (netfilter
# extensions/libxt_CLASSIFY.c), which stops the activation script.
# nftables is looser - it takes a bare number, and the two keywords `root`
# and `none` - but a bare number means a different handle there than the
# same policy would get on iptables, so it is worth saying.
_TRAFFIC_CLASS_RE = re.compile(r'[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}')


# What the address of the backup SSH rule may be made of.  The value is
# spliced into a shell command and into an nftables rule at the one moment
# the block action has already set every chain to drop, so a space, a
# quote or a shell metacharacter there costs the administrator the way
# back in - and would run whatever it says.  An address, a prefix and a
# host name all fit in this alphabet; nothing else has to.
_MGMT_ADDRESS_RE = re.compile(r'[0-9A-Za-z.:_/-]{1,255}')


def is_valid_mgmt_address(value: str) -> bool:
    """Report whether *value* can be written into the backup SSH rule."""
    return bool(_MGMT_ADDRESS_RE.fullmatch(str(value).strip()))


def mgmt_address_is_ipv6(value: str) -> bool:
    """Whether the backup SSH address belongs to the IPv6 family.

    A colon is the one character an IPv6 literal has and neither an IPv4
    address nor a host name may carry: the kernel refuses a ``:`` in an
    interface name and DNS labels are letters, digits and ``-``.  So the
    test needs nothing more, and it has to give the same answer everywhere
    the address is written out - the rule in the ruleset, the block action
    and the stop action all name a family, and one of them disagreeing
    means the rule is missing from exactly the ruleset the administrator
    needs it in.
    """
    return ':' in str(value)


def mgmt_address_family(value: str) -> str:
    """Return ``'ip6'``, ``'ip'`` or ``''`` for the backup SSH address.

    An empty answer means the value is no address literal - a host name, in
    practice - and then the rule cannot go into the *ruleset*: nftables
    resolves a name while parsing and refuses the whole ruleset when it
    answers with more than one address (src/datatype.c), and iptables would
    turn one rule into one per address at activation time.  fwbuilder asks
    the same question, by trying to construct an ``InetAddrMask`` /
    ``Inet6AddrMask`` from the value, and warns when it fails
    (``_printBackupSSHAccessRules``).

    The block and stop actions keep taking a name: they build their own
    small ruleset, so a name that resolves badly costs one command there
    rather than the firewall's whole policy.
    """
    text = str(value).strip()
    if not text:
        return ''
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return ''
    return 'ip6' if network.version == 6 else 'ip'


def is_valid_traffic_class(value: str) -> bool:
    """Report whether both packet filters read *value* as the same handle."""
    return bool(_TRAFFIC_CLASS_RE.fullmatch(str(value).strip()))


def normalize_hashlimit_mode(mode: str) -> str:
    """Return the netfilter spelling of one rate-limit key."""
    mode = mode.strip().lower()
    return _HASHLIMIT_MODE_ALIASES.get(mode, mode)


# The units a rate can be given in, in the order iptables tries them.  It
# takes any prefix of a name (extensions/libxt_limit.c and
# libxt_hashlimit.c both call strncasecmp with the length of what the user
# wrote), so `/sec`, `/m` and `/h` are all valid there.  nftables takes the
# full word and nothing else (src/parser_bison.y, time_unit), and answers a
# short one with a syntax error that costs the whole ruleset.
_RATE_UNITS = ('second', 'minute', 'hour', 'day')


def normalize_rate_unit(suffix: str) -> str | None:
    """Return the full unit name behind a rate suffix, or ``None``.

    ``None`` means the suffix names no unit netfilter knows, which is
    something the caller has to report rather than pass on.  An empty
    suffix is a rate per second, the default on both platforms.
    """
    unit = suffix.strip().lstrip('/').lower()
    if not unit:
        return 'second'
    for known in _RATE_UNITS:
        if known.startswith(unit):
            return known
    return None


# Characters the nftables preprocessor and the shell both read as syntax.
# See sanitize_log_prefix below for why none of them can be escaped.
_LOG_PREFIX_DROPPED = frozenset('$`\\')


def sanitize_log_prefix(prefix: str) -> str:
    """Return *prefix* with the characters no back end can carry removed.

    A log prefix is free text, and the macros splice a rule set name and an
    interface name into it, so it can hold anything the user typed.  It then
    has to survive two grammars that both give some characters a meaning of
    their own: the nftables parser and, on iptables, the shell that runs the
    generated script.  Three kinds of character do not make it through:

    * A double quote.  nftables has no escape for it -- its scanner reads a
      quoted string as ``\\"[^"]*\\"`` (netfilter nftables src/scanner.l), so
      the first inner quote ends the string and the rest is lexed as
      syntax.  The ruleset then fails to load as a whole and the firewall
      keeps its old rules.  In the iptables script the prefix sits inside a
      shell-quoted argument, where the shell swallows the quotes and the
      logged prefix silently loses them.  Replacing it with a single quote
      keeps the text readable and identical on both platforms.
    * ``$``, a backtick and a backslash.  nftables runs the prefix through
      its own preprocessor (netfilter nftables src/parser_bison.y hands it
      to ``str_preprocess``, src/preprocess.c), which reads a ``$`` before a
      letter or an underscore as a variable reference and refuses the whole
      ruleset with "unknown identifier".  On iptables the prefix ends up in
      a double-quoted shell word, where the very same three characters are
      the shell's variable expansion, command substitution and escape -- so
      a prefix picked up from an object name could not only mangle the text
      but run a command on the firewall at activation time.  There is no
      spelling that means the literal character in both places, so they are
      dropped.
    * A control character.  Both a rule line and a shell command line end at
      a newline, and a tab or carriage return in a kernel log message only
      confuses whatever reads it.
    """
    return ''.join(
        "'" if char == '"' else char
        for char in prefix
        if char.isprintable() and char not in _LOG_PREFIX_DROPPED
    )


# Everything the REJECT target accepts after --reject-with, primary names and
# aliases, per address family (netfilter iptables extensions/libipt_REJECT.c
# and libip6t_REJECT.c, reject_table).  REJECT_parse() compares against this
# table and calls xtables_error() on anything else, which stops the whole
# activation script, so a value coming from the rule options is checked
# against it before it reaches the command line.
REJECT_TYPES_IPV4 = frozenset(
    {
        'admin-prohib',
        'host-prohib',
        'host-unreach',
        'icmp-admin-prohibited',
        'icmp-host-prohibited',
        'icmp-host-unreachable',
        'icmp-net-prohibited',
        'icmp-net-unreachable',
        'icmp-port-unreachable',
        'icmp-proto-unreachable',
        'net-prohib',
        'net-unreach',
        'port-unreach',
        'proto-unreach',
        'tcp-reset',
        'tcp-rst',
    }
)
REJECT_TYPES_IPV6 = frozenset(
    {
        'addr-unreach',
        'adm-prohibited',
        'icmp6-addr-unreachable',
        'icmp6-adm-prohibited',
        'icmp6-no-route',
        'icmp6-policy-fail',
        'icmp6-port-unreachable',
        'icmp6-reject-route',
        'no-route',
        'policy-fail',
        'port-unreach',
        'reject-route',
        'tcp-reset',
    }
)


def reject_type_token(value: str, ipv6: bool) -> str:
    """Return the iptables ``--reject-with`` token *value* stands for.

    The GUI stores a human-readable name such as "ICMP host unreachable",
    which fwbuilder maps to a token by looking for substrings
    (``PolicyCompiler_PrintRule::_printActionOnReject``).  An imported
    ``.fwb`` may instead carry the token itself.  Both go through here, so
    the two backends pick the same ICMP message for the same rule: the
    iptables printer writes the token out, the nftables one looks up the
    code nftables calls it by.

    Returns an empty string for a value neither of the two is, which
    includes fwbuilder's own placeholders "none" and "NOP"
    (``PolicyCompiler_ipt::resetActionOnReject``).
    """
    if not value:
        return ''

    if value == 'TCP RST':
        return 'tcp-reset'

    if value.startswith('ICMP') or value == 'ICMP-unreachable':
        s = value.lower()
        if ipv6:
            # IPv6 has no net/host/protocol distinction: the kernel knows
            # only address- and port-unreachable plus admin-prohibited
            # (netfilter nftables src/datatype.c, icmpv6_code_tbl).
            if 'unreachable' in s:
                if 'port' in s or 'proto' in s:
                    return 'icmp6-port-unreachable'
                return 'icmp6-addr-unreachable'
            if 'prohibited' in s:
                return 'icmp6-adm-prohibited'
        else:
            if 'unreachable' in s:
                if 'net' in s:
                    return 'icmp-net-unreachable'
                if 'port' in s:
                    return 'icmp-port-unreachable'
                if 'proto' in s:
                    return 'icmp-proto-unreachable'
                return 'icmp-host-unreachable'
            if 'prohibited' in s:
                if 'net' in s:
                    return 'icmp-net-prohibited'
                if 'admin' in s:
                    return 'icmp-admin-prohibited'
                return 'icmp-host-prohibited'

    token = value.lower()
    if token in (REJECT_TYPES_IPV6 if ipv6 else REJECT_TYPES_IPV4):
        # Every entry of the REJECT target's reject_table has two names and
        # an imported file carries whichever the administrator picked, so
        # the alias is answered with the name the rest of the compiler
        # knows.  Only this pair differs between the two names, the others
        # are spelled the same way on both sides.
        if token == 'tcp-rst':  # nosec B105
            return 'tcp-reset'
        return token

    return ''


# What the host OS setting "IPv4/IPv6 packet forwarding" can say.  Only an
# explicit "off" means off: an empty value is "no change", which leaves the
# kernel setting alone, and a host that already forwards keeps forwarding.
_FORWARDING_OFF_VALUES = frozenset({'0', 'Off', 'off'})


def forwarding_is_off(fw, ipv6: bool) -> bool:
    """Whether the firewall is configured not to forward this family.

    The two families are separate settings and have to be asked
    separately - a host may route IPv6 and not IPv4.  fwbuilder reads the
    matching one per compilation pass
    (PolicyCompiler_ipt::finalizeChain), and reading only the IPv4 one
    would decide the IPv6 ruleset by an unrelated switch.
    """
    key = 'linux24_ipv6_forward' if ipv6 else 'linux24_ip_forward'
    return str(fw.get_option(key) or '') in _FORWARDING_OFF_VALUES


def count_bridge_interfaces(fw) -> int:
    """Return how many bridge interfaces a firewall has.

    A bridge port is matched with ``-m physdev``, which names the port and
    not the bridge it hangs on.  Several bridges can share one wildcard
    port name - ``vnet+`` on both br0 and br1 is what libvirt gives every
    host running more than one virtual network - and then the port match
    alone no longer tells them apart.  Naming the bridge next to it with
    ``-i``/``-o`` does, which is worth doing only when there is more than
    one bridge (fwbuilder PolicyCompiler_ipt::prolog, and the
    ``bridge_count > 1`` test in PolicyCompiler_PrintRule.cpp).

    Shared by the policy and the NAT compiler: both write bridge-port
    matches, and a NAT rule that cannot tell two bridges apart translates
    for the wrong one.
    """
    return sum(
        1 for iface in fw.interfaces if (iface.get_option('type', '') or '') == 'bridge'
    )


def bridge_port_match_needs_the_bridge(obj, bridge_count: int) -> bool:
    """Whether a match on this bridge port has to name its bridge as well.

    Only a wildcard port name on a firewall with more than one bridge is
    ambiguous, and only then is the extra ``-i``/``-o`` worth its cost -
    which is what :func:`count_bridge_interfaces` explains.  Both print
    rules ask this question and one more place has to ask it too: a rule
    that names the bridge cannot live in the postrouting chain, because
    iptables refuses ``-i`` there whatever the physdev match says.
    """
    if bridge_count <= 1:
        return False
    name = getattr(obj, 'name', '') or ''
    # fwbuilder stores the wildcard as `*`, the print rules rewrite it to
    # the `+` iptables spells it, and this is asked from both sides.
    if not name.endswith(('*', '+')):
        return False
    parent = getattr(obj, 'parent_interface', None)
    return bool(parent is not None and parent.name)


def strip_mac_objects(objects) -> tuple[list, str]:
    """Take the ethernet half out of *objects*, keeping every address half.

    Returns the objects that survive and the name of the first one that
    carried a MAC, or an empty name when none did.

    ``PolicyCompiler_ipt::checkMACinOUTPUTChain`` (PolicyCompiler_ipt.cpp:
    3613) and ``NATCompiler_ipt::verifyRuleWithMAC`` (NATCompiler_ipt.cpp:
    2288) both make the same distinction, and it is the whole point of the
    check: a bare physAddress is nothing but a MAC, so removing it empties
    the element and the rule has to go, but a combined address - which is
    what a host with "MAC address matching" expands to, and therefore the
    usual shape here - is an address *and* a MAC, and the address half is a
    match the chain can perfectly well make.  fwbuilder clears the MAC with
    ``setPhysAddress("")`` and keeps the rule.

    Dropping such a rule instead loses a rule the administrator wrote,
    which is fail-closed on an Accept and fail-open on a Deny.
    """
    kept = []
    mac_name = ''
    for obj in objects:
        if isinstance(obj, PhysAddress):
            mac_name = mac_name or obj.name
            continue
        if isinstance(obj, CombinedAddress) and obj.has_phys_address():
            mac_name = mac_name or obj.name
            if not obj.is_address_any():
                kept.append(obj.address)
            continue
        if get_mac_only_address(obj):
            mac_name = mac_name or obj.name
            continue
        kept.append(obj)
    return kept, mac_name


def get_mac_only_address(obj) -> str:
    """Return the MAC of an object that has no IP address.

    A PhysAddress, or an Interface / Host whose only address is a MAC, can
    only be matched on the ethernet header.  Rendering such an object as an
    IP address produces a ruleset the packet filter refuses to load.

    The value is returned as it is stored, because the guards that ask
    whether an object carries a MAC at all have to see one even when it is
    unusable - ``VerifyMacAddresses`` is what decides that, and it leaves
    the whole rule out.  Only the print rules normalise, on the way into
    the command.
    """
    if isinstance(obj, PhysAddress):
        return obj.get_address() or ''
    if isinstance(obj, Interface):
        addresses = list(getattr(obj, 'addresses', []))
    elif isinstance(obj, Host):
        addresses = [
            addr
            for iface in getattr(obj, 'interfaces', [])
            if not iface.is_loopback()
            for addr in getattr(iface, 'addresses', [])
        ]
    else:
        return ''
    if any(addr.is_v4() or addr.is_v6() for addr in addresses):
        return ''
    for addr in addresses:
        if isinstance(addr, PhysAddress) and addr.get_address():
            return addr.get_address()
    return ''


def get_tag_value(compiler, rule) -> str:
    """Return the packet mark a tagging rule sets, or an empty string.

    Ports ``PolicyRule::getTagValue()``
    (libfwbuilder/src/fwbuilder/Rule.cpp:571), which has two sources and
    asks them in this order: the Tag Service object the rule names carries
    the mark, and *if there is no such object* the mark is read straight
    off the rule option ``tagvalue``.

    That second half is how Firewall Builder stored a tag before Tag
    Service objects existed, and it still reads it - so a policy written
    with an older release compiles there and had its tagging rules
    reported and left out here.
    """
    tag_id = rule.get_option('tagobject_id', '')
    if tag_id:
        try:
            tag_obj = compiler.session.get(TagService, uuid.UUID(str(tag_id)))
        except (AttributeError, ValueError):
            tag_obj = None
        if tag_obj:
            return tag_obj.get_code() or ''
    return str(rule.get_option('tagvalue', '') or '').strip()


# Interfaces whose names differ only in a trailing number are one group,
# named after the pattern that matches them all: eth0, eth1 and eth2
# become `eth+`.  fwbuilder builds that map once per compiler
# (`build_interface_groups`, iptlib/ipt_utils.cpp) and uses it wherever a
# rule has to name "the firewall's interfaces" without naming one:
# a source translation whose translated address belongs to none of them,
# and a rule that says inbound or outbound and no interface.  One `-o eth+`
# is not only shorter than one rule per interface, it also covers the
# interface that gets added next.
_INTERFACE_INDEX = re.compile(r'[0-9]+$')


class _AnyInterface:
    """Stands for "every interface of this firewall" in a rule element.

    A rule that names a direction and no interface still has to say which
    of the two it is, and Firewall Builder says it by putting a group named
    ``*`` into the Itf element (``PolicyCompiler_ipt::InterfaceAndDirection``
    together with ``build_interface_groups``).  The print rules then write
    ``-i +`` / ``-o +``, and ``optimizeForMinusIOPlus`` takes it out again
    in the INPUT and OUTPUT chains, whose hook already answers the
    question.  Everywhere else - a branch rule set above all, whose chain
    is reached from INPUT *and* OUTPUT - the match is what keeps an
    "Outbound" rule from applying to incoming traffic as well.

    Deliberately not an ``Interface``: fwbuilder puts an ObjectGroup there,
    so every ``Interface::cast`` in the compiler answers null for it, and
    every ``isinstance(obj, Interface)`` here has to answer the same.
    """

    __slots__ = ()

    name = '*'


#: The single instance; it carries no state.
ANY_INTERFACE = _AnyInterface()


def interface_group_name(name: str) -> str:
    """Return the pattern that matches *name* and its siblings.

    Spelled with the trailing ``*`` Firewall Builder stores for a wildcard
    interface; the iptables printer turns that into the ``+`` iptables
    wants and nftables takes the glob as it is.
    """
    return _INTERFACE_INDEX.sub('*', name)


def build_interface_groups(fw, ipv6: bool) -> dict[str, list]:
    """Group the firewall's regular interfaces by name pattern.

    Left out, the way fwbuilder leaves them out: the loopback, an
    unnumbered interface and a bridge port, none of which a rule about
    "the firewall's interfaces" can mean.  An interface is also left out
    when it carries an address of the *other* family only - the rule being
    compiled could never match on it.  An interface with no address at all
    stays: a dynamic one gets its address at run time.

    The key ``'*'`` holds every interface that survived, which is what a
    rule naming a direction and no interface means.
    """
    from firewallfabrik.core.objects import IPv4, IPv6

    groups: dict[str, list] = {'*': []}
    for iface in fw.interfaces:
        if iface.is_loopback() or iface.is_unnumbered() or iface.is_bridge_port():
            continue
        addresses = iface.addresses or []
        has_v4 = any(isinstance(address, IPv4) for address in addresses)
        has_v6 = any(isinstance(address, IPv6) for address in addresses)
        if (has_v4 or has_v6) and not (has_v6 if ipv6 else has_v4):
            continue
        groups.setdefault(interface_group_name(iface.name), []).append(iface)
        groups['*'].append(iface)
    return groups


def interface_group_object(fw, group_name: str):
    """Return a stand-in Interface object named after an interface group.

    A rule element holds objects and the printer writes their names, so
    the group needs an object of its own.  fwbuilder puts an ObjectGroup
    there; here a detached Interface carrying the pattern as its name is
    the smaller answer, and it answers the predicates the printers ask
    (it is no loopback, no bridge port and no sub-interface).
    """
    from firewallfabrik.core.objects import Interface

    return Interface(
        id=uuid.uuid4(),
        name=group_name,
        device_id=fw.id,
        data={},
        options={},
    )
