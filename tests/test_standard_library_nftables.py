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

"""The Custom Services the standard library ships, on nftables.

A Custom Service carries one code per platform and the compiler writes
that code into the rule as it stands.  The ten the standard library
inherited from Firewall Builder carry no nftables code, because Firewall
Builder never had the platform - so a rule naming one is reported and left
out there while it compiles on iptables.

Only the two "ESTABLISHED" services have an nftables equivalent.  The rest
are matches nftables does not have: `-m psd` and `-m string` do not exist
in it, `-m record_rpc` left netfilter with patch-o-matic, `-m irc` and
`-m talk` are connection-tracking helpers, and the three Junos fragment
services carry no iptables code either.
"""

import pathlib

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import CustomService
from firewallfabrik.platforms.linux._netfilter import custom_service_matches_state

LIBRARY = (
    pathlib.Path(__file__).parents[1]
    / 'src'
    / 'firewallfabrik'
    / 'resources'
    / 'libraries'
    / 'standard.fwf'
)

WITH_NFTABLES_CODE = {'ESTABLISHED', 'ESTABLISHED ipv6'}


@pytest.fixture(scope='module')
def services():
    dm = firewallfabrik.core.DatabaseManager('sqlite://')
    dm.load(str(LIBRARY))
    with dm.session() as session:
        return {
            service.name: dict(service.codes or {})
            for service in session.scalars(sqlalchemy.select(CustomService)).all()
        }


def test_the_established_services_carry_nftables_code(services):
    for name in WITH_NFTABLES_CODE:
        assert services[name].get('nftables') == 'ct state established,related'


def test_that_code_is_recognised_as_matching_the_state(services):
    """Or the compiler would add its own `ct state new` beside it.

    `SpecialCasesWithCustomServices` marks a rule stateless when the
    custom code does its own connection-state matching, and it has to give
    the same answer on both platforms for one and the same object.
    """
    for name in WITH_NFTABLES_CODE:
        codes = services[name]
        assert custom_service_matches_state(codes['nftables'])
        assert custom_service_matches_state(codes['iptables'])


def test_no_other_custom_service_claims_an_nftables_equivalent(services):
    claiming = {name for name, codes in services.items() if codes.get('nftables')}
    assert claiming == WITH_NFTABLES_CODE
