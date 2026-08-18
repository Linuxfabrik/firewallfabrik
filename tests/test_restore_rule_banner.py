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

"""What the banner above a rule carries in the iptables-restore format.

fwbuilder writes three parts above every rule and writes them in every
output format, because the same method produces them
(`Compiler::printComment`, Compiler.cpp:1763, reached from both
`PrintRuleIptRst::_printRuleLabel` and the Echo variant that inherits it):
the rule label, the comment the administrator wrote about the rule, and
whatever the compiler reported about it.

The two restore printers of this port answered with the label alone, so a
firewall activating through `iptables-restore` had every rule comment and
every compiler message missing from its script.  The reference output for
firewall35 shows both lines (`firewall35.fw.orig:317`).

The one part the restore format must *not* carry is the shell form's
`echo "Rule N"` progress line: those lines go into the stream
`iptables-restore` reads, which takes rules and comments and nothing else.
"""

import pytest

from firewallfabrik.platforms.iptables._nat_print_rule import (
    NATPrintRule,
    NATPrintRuleIptRstEcho,
)
from firewallfabrik.platforms.iptables._print_rule import PrintRule, PrintRuleIptRstEcho


class _Compiler:
    single_rule_compile_mode = False


class _Rule:
    label = '3 (eth0)'
    comment = 'only the mail relay may talk to the outside'
    compiler_message = '# Rule 3 (eth0): the MAC match was left out'


def _banner(printer_class):
    printer = printer_class()
    printer.compiler = _Compiler()
    return printer._print_rule_label(_Rule())


@pytest.mark.parametrize(
    'printer_class',
    [PrintRule, PrintRuleIptRstEcho, NATPrintRule, NATPrintRuleIptRstEcho],
)
def test_every_format_carries_the_label_comment_and_message(printer_class):
    banner = _banner(printer_class)

    assert '# Rule 3 (eth0)' in banner
    assert '# only the mail relay may talk to the outside' in banner
    assert '# Rule 3 (eth0): the MAC match was left out' in banner


@pytest.mark.parametrize('printer_class', [PrintRule, NATPrintRule])
def test_the_shell_format_says_which_rule_it_is_installing(printer_class):
    assert 'echo "Rule 3 (eth0)"' in _banner(printer_class)


@pytest.mark.parametrize('printer_class', [PrintRuleIptRstEcho, NATPrintRuleIptRstEcho])
def test_the_restore_format_puts_nothing_but_rules_into_the_stream(printer_class):
    """An `echo` here is a line iptables-restore has to read."""
    banner = _banner(printer_class)

    assert 'echo' not in banner
    assert all(line.startswith('#') for line in banner.splitlines() if line)
