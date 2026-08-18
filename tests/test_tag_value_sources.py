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

"""Where a tagging rule takes the packet mark it sets.

`PolicyRule::getTagValue()` (libfwbuilder/src/fwbuilder/Rule.cpp:571) has
two sources and asks them in order: the Tag Service object the rule names
carries the mark, and if the rule names no such object the mark is read
straight off the rule option ``tagvalue``.  That second half is how
Firewall Builder stored a tag before Tag Service objects existed, and it
still reads it, which is why a policy written with an older release still
compiles there.

Both print rules asked only the first source and answered an empty string
for the second, whereupon the rule is reported and left out - the mark
never gets set, and every rule and routing decision keyed on it sees
traffic the policy says is marked and finds it is not.
"""

import uuid

import pytest

from firewallfabrik.core.objects import TagService
from firewallfabrik.platforms.linux._netfilter import get_tag_value


class _Session:
    def __init__(self, obj=None) -> None:
        self._obj = obj

    def get(self, _cls, _key):
        return self._obj


class _Compiler:
    def __init__(self, session) -> None:
        self.session = session


class _Rule:
    def __init__(self, **options) -> None:
        self._options = options

    def get_option(self, key, default=None):
        return self._options.get(key, default)


def _tag_service(code):
    service = TagService(id=uuid.uuid4(), name='mark 16')
    service.data = {'tagcode': code}
    return service


def test_the_mark_comes_from_the_tag_service_the_rule_names():
    service = _tag_service('16')
    rule = _Rule(tagobject_id=str(service.id))

    assert get_tag_value(_Compiler(_Session(service)), rule) == '16'


def test_a_rule_naming_no_tag_service_falls_back_to_the_stored_value():
    """The representation Firewall Builder used before Tag Service objects."""
    rule = _Rule(tagvalue='16')

    assert get_tag_value(_Compiler(_Session()), rule) == '16'


def test_the_tag_service_wins_over_the_stored_value():
    """`getTagValue` asks the object first and the option only without one."""
    service = _tag_service('32')
    rule = _Rule(tagobject_id=str(service.id), tagvalue='16')

    assert get_tag_value(_Compiler(_Session(service)), rule) == '32'


def test_a_tag_service_that_is_gone_leaves_the_stored_value():
    """An id pointing at nothing is the same case as no id at all."""
    rule = _Rule(tagobject_id=str(uuid.uuid4()), tagvalue='16')

    assert get_tag_value(_Compiler(_Session()), rule) == '16'


@pytest.mark.parametrize('options', [{}, {'tagvalue': ''}, {'tagvalue': '   '}])
def test_a_rule_with_no_mark_anywhere_answers_nothing(options):
    """The caller reads that as "report the rule and leave it out"."""
    assert get_tag_value(_Compiler(_Session()), _Rule(**options)) == ''


@pytest.mark.parametrize('platform', ['iptables', 'nftables'])
def test_both_printers_ask_the_same_question(platform):
    """The two had a private copy each, and only one had to drift."""
    import inspect

    module = __import__(
        f'firewallfabrik.platforms.{platform}._print_rule', fromlist=['x']
    )
    source = inspect.getsource(module)

    assert 'get_tag_value(self.compiler, rule)' in source
    assert 'def _get_tag_value' not in source
