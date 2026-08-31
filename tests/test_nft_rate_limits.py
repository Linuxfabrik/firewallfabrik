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

"""The rate limit an nftables rule carries, against the netfilter translator.

The editor's "Limit matching rate" is a ceiling: the rule matches while the
traffic stays below it.  iptables says that with ``--hashlimit <n>``, the old
spelling of ``--hashlimit-upto``, and nftables with a plain ``limit rate``.
``limit rate over`` is the opposite and belongs to ``--hashlimit-above``,
which the editor cannot ask for.  Both mappings sit side by side in the gold
the netfilter tree ships, and can be reproduced with

    iptables-translate -A OUTPUT -m hashlimit --hashlimit-upto 300 \\
        --hashlimit-burst 15 --hashlimit-name https
    iptables-translate -A OUTPUT -m hashlimit --hashlimit-above 20kb/s \\
        --hashlimit-name https
"""

import pytest

from firewallfabrik.platforms.linux._netfilter import normalize_hashlimit_mode
from firewallfabrik.platforms.nftables._print_rule import PrintRule_nft


class _Rule:
    """The bit of a rule the rate printer reads."""

    def __init__(self, **options):
        self._options = options

    def get_option(self, key, default=None):
        return self._options.get(key, default)


class _Compiler:
    """The bit of PolicyCompiler_nft the rate printer reaches for."""

    def __init__(self):
        self.errors = []
        self.warnings = []

    def error(self, rule, message):
        self.errors.append(message)

    def warning(self, rule, message):
        self.warnings.append(message)


def _printer():
    printer = PrintRule_nft(name='PrintRule_nft')
    printer.compiler = _Compiler()
    return printer


@pytest.mark.parametrize(
    ('options', 'expected'),
    [
        # The plain case: a ceiling, so no `over`.
        ({}, 'limit rate 300/second'),
        # The suffix the editor stores is passed through as it stands.
        ({'hashlimit_suffix': '/hour'}, 'limit rate 300/hour'),
        # A burst is a packet count, unlike the byte burst `--hashlimit-burst`
        # takes for a byte rate.
        ({'hashlimit_burst': 15}, 'limit rate 300/second burst 15 packets'),
        ({'hashlimit_burst': 0}, 'limit rate 300/second'),
    ],
)
def test_hashlimit_rate_is_a_ceiling(options, expected):
    assert _printer()._hashlimit_rate(_Rule(**options), 300) == expected


def test_hashlimit_rate_never_says_over():
    """`over` inverts the match and would let exactly the excess through."""
    rate = _printer()._hashlimit_rate(_Rule(hashlimit_burst=2), 1)
    assert 'over' not in rate


def test_the_v2_1_spellings_of_the_key_are_normalised():
    """netfilter takes only the short ones.

    Firewall Builder 2.1 stored one string for the key, and an imported
    file can still carry it.  ``--hashlimit-mode destip`` is answered with
    "Bad value for --hashlimit-mode" by the real iptables, and the nftables
    side read the token as unknown and dropped the key altogether, which
    turned a per-destination limit into a limit for the rule as a whole.
    """
    assert normalize_hashlimit_mode('destip') == 'dstip'
    assert normalize_hashlimit_mode('destport') == 'dstport'
    assert normalize_hashlimit_mode('sourceip') == 'srcip'
    assert normalize_hashlimit_mode(' DstIP ') == 'dstip'
    # Anything already spelled the way netfilter wants it is left alone.
    assert normalize_hashlimit_mode('srcport') == 'srcport'


@pytest.mark.parametrize(
    ('suffix', 'expected'),
    [
        # iptables takes any prefix of a unit name, nftables the full word
        # alone, so what an imported file carries has to be written out.
        ('/sec', 'limit rate 300/second'),
        ('/min', 'limit rate 300/minute'),
        ('/h', 'limit rate 300/hour'),
        ('/d', 'limit rate 300/day'),
        ('/second', 'limit rate 300/second'),
        ('', 'limit rate 300/second'),
    ],
)
def test_a_short_rate_unit_is_written_out(suffix, expected):
    printer = _printer()
    assert printer._hashlimit_rate(_Rule(hashlimit_suffix=suffix), 300) == expected
    assert printer.compiler.errors == []


def test_a_unit_that_names_nothing_leaves_the_rule_out():
    """Passing it on would be a syntax error and cost the whole ruleset.

    Falling back to a default unit is not the answer either: per second is
    sixty times what a rule written per minute asks for, so the firewall
    would enforce a rate the editor never showed.  The iptables printer
    leaves the rule out for the same reason.
    """
    printer = _printer()
    assert printer._hashlimit_rate(_Rule(hashlimit_suffix='/fortnight'), 300) is None
    assert any('not a unit' in message for message in printer.compiler.errors)


def test_a_burst_nftables_would_cut_down_leaves_the_rule_out():
    """The burst travels in 32 bits and a larger one is silently truncated.

    A burst of exactly 2^32 arrives as zero, which the kernel replaces with
    its default of five: the rule then bursts five packets where it was
    written for four billion.  Verified against nft 1.1.6 in a network
    namespace.
    """
    printer = _printer()
    assert printer._hashlimit_rate(_Rule(hashlimit_burst=2**32), 300) is None
    assert any('out of range' in message for message in printer.compiler.errors)


@pytest.mark.parametrize(
    ('line', 'merges_on'),
    [
        # An ordinary rule still merges on its address.
        ('ip saddr 10.0.0.1 tcp dport 22 counter accept', 'saddr'),
        # The `ip saddr` of a connection limit is the key of its set, not
        # the rule's address match: merging two of these would write a set
        # inside the braces, which nftables answers with a syntax error.
        ('iifname "eth0" add @s { ip saddr ct count over 10 } counter drop', None),
        ('meter m { ip saddr . th sport limit rate 20/second } counter drop', None),
        # The other side of such a rule is still a real address match.
        (
            'ip daddr 10.0.0.1 add @s { ip saddr ct count over 10 } counter drop',
            'daddr',
        ),
    ],
)
def test_the_set_merge_ignores_an_address_inside_a_rate_limit(line, merges_on):
    from firewallfabrik.platforms.nftables._print_rule import _parse_addr

    parsed = _parse_addr(line)
    assert (parsed[3] if parsed else None) == merges_on


class _FirewallWithLogLimit:
    """The bit of the firewall object the log-rate lookup reaches for."""

    @staticmethod
    def get_option(key):
        return 5 if key == 'limit_value' else ''


class _LoggedRule(_Rule):
    """A rule the printer would split into a log line and a verdict line."""

    nft_log = True


@pytest.mark.parametrize(
    'options',
    [
        {},
        # A meter and a connection limit are stateful, and a rule carrying
        # one no longer reaches the printer with a log on it:
        # `SplitLogWithStatefulLimit` has put it in a chain of its own by
        # then, so the pair this decides about is always one both lines may
        # hold.
        {'hashlimit_value': 20},
        {'connlimit_value': 5},
        {'limit_value': 20},
    ],
)
def test_a_logged_rule_splits_where_the_firewall_caps_its_log_rate(options):
    printer = _printer()
    printer.compiler.fw = _FirewallWithLogLimit()
    printer.compiler.log_rate_limit = lambda: 5
    assert printer._splits_for_log(_LoggedRule(**options)) is True


def test_a_logged_rule_stays_whole_where_nothing_caps_the_log_rate():
    printer = _printer()
    printer.compiler.fw = _FirewallWithLogLimit()
    printer.compiler.log_rate_limit = lambda: 0
    assert printer._splits_for_log(_LoggedRule()) is False


@pytest.mark.parametrize(
    ('ipv6', 'masklen', 'refused'),
    [
        (False, 24, False),
        (False, 32, False),
        (False, 33, True),
        (False, 64, True),
        (True, 64, False),
        (True, 128, False),
        (True, 129, True),
    ],
)
def test_a_connection_limit_groups_by_at_most_the_address_width(ipv6, masklen, refused):
    """The iptables printer has refused this since it was written.

    A prefix wider than the family has no group to count by.  Dropping just
    the mask counts per single address, which is a different limit from the
    one the rule carries - and the same policy then means two different
    things on the two platforms, with only one of them saying so.
    """
    printer = _printer()
    printer.compiler.ipv6_policy = ipv6
    printer.compiler.get_rule_set_name = lambda: 'Policy'
    printer.compiler.register_dynamic_set = lambda *args: None
    rule = _Rule(connlimit_value=2, connlimit_masklen=masklen)
    rule.position = 0
    out = printer._print_connlimit(rule)
    if refused:
        assert out is None
        assert any('groups by at most' in m for m in printer.compiler.errors)
    else:
        assert out is not None and 'ct count' in out
        assert printer.compiler.errors == []


def test_a_log_prefix_longer_than_nftables_carries_is_reported():
    """Cutting it keeps the ruleset loadable, but a log parser has to know.

    NF_LOG_PREFIXLEN is 128 and holds the terminator (netfilter
    linux/include/uapi/linux/netfilter/nf_log.h), and nft answers a longer
    prefix with "log prefix is too long" and refuses the whole ruleset -
    verified against nft 1.1.6.  So the prefix is cut, and now said so, the
    way the iptables printer has always said it for its own shorter limits.
    """
    from firewallfabrik.platforms.nftables._print_rule import MAX_NFT_LOG_PREFIX

    printer = _printer()
    printer.compiler.source_ruleset = None
    rule = _Rule(log_prefix='x' * 200)
    rule.stored_action = 'ACCEPT'
    rule.position = 0
    rule.ipt_chain = 'input'
    rule.itf = []
    out = printer._get_log_prefix(rule)
    assert len(out) == MAX_NFT_LOG_PREFIX
    assert any('has been truncated' in message for message in printer.compiler.warnings)


def test_the_entry_ceiling_of_a_rate_limit_table_reaches_the_meter():
    """--hashlimit-htable-max bounds how many sources the table holds.

    A meter's implicit set takes the same bound as `size`, and without one
    it grows until the set is full and then stops limiting anything it has
    not seen yet.  The iptables printer has written the option out since
    the match was added; the nftables one never read it, although the
    grammar has the slot (netfilter nftables src/parser_bison.y,
    `METER identifier SIZE NUM`).  Offered to nft 1.1.6, which declares the
    set with `size 128`.
    """
    printer = _printer()
    printer.compiler.meters = {}
    printer.compiler.ipv6_policy = False
    printer.compiler.get_rule_set_name = lambda: 'Policy'
    printer.compiler.register_meter = lambda *_args: (True, True)
    rule = _Rule(hashlimit_value=10, hashlimit_max=128, hashlimit_mode_srcip=True)
    rule.position = 0
    rule.srv = []
    out = printer._print_hashlimit(rule)
    assert out.startswith('meter htable_Policy_0 size 128 {')


def _meter_printer():
    """A printer wired to the real meter registry of PolicyCompiler_nft."""
    from firewallfabrik.platforms.nftables._policy_compiler import PolicyCompiler_nft

    printer = _printer()
    printer.compiler.meters = {}
    printer.compiler.ipv6_policy = False
    printer.compiler.muted_now = False
    printer.compiler.get_rule_set_name = lambda: 'Policy'
    printer.compiler.register_meter = lambda *args: PolicyCompiler_nft.register_meter(
        printer.compiler, *args
    )
    return printer


def _meter_rule(position, **options):
    """A rule on a TCP service, so a port key is one the kernel can read."""
    import uuid

    from firewallfabrik.core.objects import TCPService

    rule = _Rule(hashlimit_value=10, hashlimit_name='shared', **options)
    rule.position = position
    rule.srv = [TCPService(id=uuid.uuid4(), name='http')]
    return rule


def test_two_rules_may_share_a_rate_limit_table_of_the_same_shape():
    printer = _meter_printer()
    first = printer._print_hashlimit(_meter_rule(0, hashlimit_mode_srcip=True))
    second = printer._print_hashlimit(_meter_rule(1, hashlimit_mode_srcip=True))

    assert first == second
    assert printer.compiler.errors == []


def test_a_rule_keying_a_shared_rate_limit_table_differently_is_left_out():
    """The kernel takes the second rule and reinterprets its key.

    A meter is a typed set, created with the key type of the first rule
    that names it.  Loading such a ruleset in a network namespace shows
    nftables accepting a rule that writes a `tcp dport` into an
    `ipv4_addr` set without a word, so neither rule limits what it says.
    """
    printer = _meter_printer()
    printer._print_hashlimit(_meter_rule(0, hashlimit_mode_srcip=True))
    second = printer._print_hashlimit(_meter_rule(1, hashlimit_mode_dstport=True))

    assert second is None
    assert any('already in use' in message for message in printer.compiler.errors)


def test_a_rule_sharing_a_rate_limit_table_at_another_rate_is_reported():
    """nftables takes it, and the first rule's rate is the one that counts.

    The rate lives in the element rather than in the set, and the element
    belongs to whichever rule saw the key first: `nft_dynset_eval` hands
    back the existing entry and evaluates the expression stored in it
    (net/netfilter/nft_dynset.c).  Loading both rules in a network
    namespace shows nft accepting them and listing two different rates on
    one set, which is why this is a warning and not an error - the same
    answer the iptables side gives for a shared hash table.
    """
    printer = _meter_printer()
    first = printer._print_hashlimit(_meter_rule(0, hashlimit_mode_srcip=True))
    second = _meter_rule(1, hashlimit_mode_srcip=True)
    second._options['hashlimit_value'] = 99
    printed = printer._print_hashlimit(second)

    assert first is not None
    assert printed is not None
    assert printer.compiler.errors == []
    assert any(
        'already in use by another rule with a different rate' in message
        for message in printer.compiler.warnings
    )


def test_the_shape_is_not_claimed_while_the_compiler_is_rehearsing():
    """`Optimize3` renders every rule once more and may then drop it.

    Claiming the name there would report the next rule against a meter no
    rule in the ruleset declares.  The iptables `_check_hashlimit_table`
    returns early for the same reason.
    """
    printer = _meter_printer()
    printer.compiler.muted_now = True
    rehearsed = printer._print_hashlimit(_meter_rule(0, hashlimit_mode_srcip=True))
    printer.compiler.muted_now = False

    assert rehearsed is not None
    assert printer.compiler.meters == {}
    assert (
        printer._print_hashlimit(_meter_rule(1, hashlimit_mode_dstport=True))
        is not None
    )
    assert printer.compiler.errors == []
