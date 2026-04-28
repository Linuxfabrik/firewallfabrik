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

"""Tests for DynamicGroup match-mode (AND vs OR) in the compiler helper.

The default match mode for new groups is AND. Groups imported from a
fwbuilder ``.fwb`` file carry an explicit ``match_mode='OR'`` to
preserve fwbuilder's original semantics
(``DynamicGroup::isMemberOfGroup()`` only supports OR).
"""

from firewallfabrik.compiler._compiler import _matches_dynamic_criteria


class _Library:
    def __init__(self, name='User'):
        self.name = name


class _FakeObj:
    """Minimal stub matching what _matches_dynamic_criteria reads."""

    def __init__(self, type_, keywords=None, library_name='User'):
        self.type = type_
        self.keywords = set(keywords or [])
        self.library = _Library(library_name)
        self.parent_group = None  # not a group, depth check skipped


def _crit(type_, keyword):
    return {'type': type_, 'keyword': keyword}


class TestSingleCriterion:
    """One criterion: AND and OR behave identically."""

    def test_match_and_default(self):
        obj = _FakeObj('Firewall', keywords={'prod03'})
        assert _matches_dynamic_criteria(obj, [_crit('Firewall', 'prod03')])

    def test_match_or(self):
        obj = _FakeObj('Firewall', keywords={'prod03'})
        assert _matches_dynamic_criteria(
            obj,
            [_crit('Firewall', 'prod03')],
            match_mode='OR',
        )

    def test_no_match_and(self):
        obj = _FakeObj('Firewall', keywords={'prod01'})
        assert not _matches_dynamic_criteria(
            obj,
            [_crit('Firewall', 'prod03')],
        )

    def test_no_match_or(self):
        obj = _FakeObj('Firewall', keywords={'prod01'})
        assert not _matches_dynamic_criteria(
            obj,
            [_crit('Firewall', 'prod03')],
            match_mode='OR',
        )


class TestMultiCriterionAndDefault:
    """Default AND: every criterion must match (real-world Klaus use case)."""

    def test_and_all_match(self):
        obj = _FakeObj('Firewall', keywords={'monitoring', 'prod03'})
        criteria = [
            _crit('Firewall', 'monitoring'),
            _crit('Firewall', 'prod03'),
        ]
        assert _matches_dynamic_criteria(obj, criteria)

    def test_and_one_missing(self):
        # Object only carries one of the two required tags.
        obj = _FakeObj('Firewall', keywords={'monitoring'})
        criteria = [
            _crit('Firewall', 'monitoring'),
            _crit('Firewall', 'prod03'),
        ]
        assert not _matches_dynamic_criteria(obj, criteria)

    def test_and_neither(self):
        obj = _FakeObj('Firewall', keywords={'unrelated'})
        criteria = [
            _crit('Firewall', 'monitoring'),
            _crit('Firewall', 'prod03'),
        ]
        assert not _matches_dynamic_criteria(obj, criteria)


class TestMultiCriterionOr:
    """OR: at least one criterion must match (fwbuilder-imported groups)."""

    def test_or_one_match(self):
        obj = _FakeObj('Firewall', keywords={'monitoring'})
        criteria = [
            _crit('Firewall', 'monitoring'),
            _crit('Firewall', 'prod03'),
        ]
        assert _matches_dynamic_criteria(obj, criteria, match_mode='OR')

    def test_or_other_match(self):
        obj = _FakeObj('Firewall', keywords={'prod03'})
        criteria = [
            _crit('Firewall', 'monitoring'),
            _crit('Firewall', 'prod03'),
        ]
        assert _matches_dynamic_criteria(obj, criteria, match_mode='OR')

    def test_or_neither(self):
        obj = _FakeObj('Firewall', keywords={'unrelated'})
        criteria = [
            _crit('Firewall', 'monitoring'),
            _crit('Firewall', 'prod03'),
        ]
        assert not _matches_dynamic_criteria(obj, criteria, match_mode='OR')

    def test_or_cross_type_union(self):
        # Classic OR use case: a group covering both Hosts and Networks
        # tagged 'production'. AND would match nothing because no object
        # is both a Host and a Network.
        host = _FakeObj('Host', keywords={'production'})
        criteria = [
            _crit('Host', 'production'),
            _crit('Network', 'production'),
        ]
        assert _matches_dynamic_criteria(host, criteria, match_mode='OR')
        assert not _matches_dynamic_criteria(host, criteria)  # AND -> no


class TestEdgeCases:
    def test_empty_criteria(self):
        obj = _FakeObj('Firewall', keywords={'prod03'})
        assert not _matches_dynamic_criteria(obj, [])

    def test_only_inactive_criteria(self):
        # 'none' / ',' marker rows are ignored as inactive (matches
        # fwbuilder's makeFilter which returns false when type==TYPE_NONE
        # or keyword==KEYWORD_NONE).
        obj = _FakeObj('Firewall', keywords={'prod03'})
        criteria = [_crit('none', 'prod03'), _crit('Firewall', ',')]
        assert not _matches_dynamic_criteria(obj, criteria)

    def test_active_and_inactive_mixed_and(self):
        # AND with one active criterion that matches and one inactive
        # row: inactive rows are skipped, AND succeeds.
        obj = _FakeObj('Firewall', keywords={'prod03'})
        criteria = [_crit('Firewall', 'prod03'), _crit('none', 'foo')]
        assert _matches_dynamic_criteria(obj, criteria)

    def test_excluded_object_type(self):
        # IPService is not in _DG_ELIGIBLE.
        obj = _FakeObj('IPService', keywords={'prod03'})
        assert not _matches_dynamic_criteria(
            obj,
            [_crit('IPService', 'prod03')],
        )

    def test_deleted_objects_library_excluded(self):
        obj = _FakeObj('Firewall', keywords={'prod03'}, library_name='Deleted Objects')
        assert not _matches_dynamic_criteria(
            obj,
            [_crit('Firewall', 'prod03')],
        )
