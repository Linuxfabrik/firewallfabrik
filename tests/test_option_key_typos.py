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

"""A firewall option key that is one edit away from a real one.

``get_option()`` falls back to the schema whenever a key is absent, so a
misspelled key is not an error, it is silence: the compiler uses the
default and the value the administrator typed is never read.  That is the
failure the option schema was written to prevent
(docs/developer-guide/PlatformDefaults.md), and the check that would have
caught it had no caller.

Reporting every unknown key is no use.  A data file imported from Firewall
Builder carries the options of every platform it ever knew - pf, pix, ipf,
iosacl - and none of those is a mistake here.  Over the whole test corpus
this check says nothing at all.
"""

from firewallfabrik.driver._compiler_driver import CompilerDriver


class _Firewall:
    platform = 'iptables'
    host_os = 'linux24'


class _Driver(CompilerDriver):
    def __init__(self):
        self.said = []

    def warning(self, message):
        self.said.append(message)


def _warnings(options):
    driver = _Driver()
    driver._warn_misspelled_options(options, _Firewall())
    return driver.said


def test_a_misspelled_key_is_named_together_with_the_one_it_resembles():
    said = _warnings({'log_perfix': 'RULE %N '})
    assert len(said) == 1
    assert 'log_perfix' in said[0]
    assert 'log_prefix' in said[0]


def test_a_key_of_another_platform_says_nothing():
    """An imported file is full of them and none of them is a mistake."""
    assert _warnings({'pix_nat_bypass': True, 'iosacl_acl_basic': 1}) == []


def test_a_key_the_compiler_knows_says_nothing():
    assert _warnings({'accept_established': True, 'log_prefix': 'x'}) == []


def test_a_name_firewall_builder_writes_says_nothing():
    """Every imported `.fwb` carries these, and none of them is a slip.

    `install_script` is close enough to `installScript`, `log_limit_suffix`
    to `limit_suffix` and `activation` to `activationCmd` for a similarity
    ratio to call all three a typo - which told 46 of the 47 firewalls of
    the reference corpus that Firewall Builder had mistyped its own option
    names.  None of them is within one edit.
    """
    assert (
        _warnings(
            {
                'activation': '',
                'install_script': '',
                'log_limit_suffix': '/second',
            }
        )
        == []
    )


def test_the_slips_a_hand_makes_are_all_covered():
    """One letter dropped, added, replaced, or two of them swapped."""
    for typed in (
        'acept_established',  # dropped
        'acccept_established',  # added
        'accapt_established',  # replaced
        'accept_estbalished',  # swapped
    ):
        said = _warnings({typed: True})
        assert len(said) == 1, typed
        assert 'accept_established' in said[0], typed


def test_a_setting_the_compiler_does_not_implement_is_named():
    """The option is in the schema, the script does not act on it.

    Both belong to the bonding and VLAN interface configuration
    (https://github.com/Linuxfabrik/firewallfabrik/issues/95), which
    Firewall Builder writes into the generated script and this compiler
    does not.  Without a word the administrator gets a script that comes
    up without the interfaces the rules are written for.
    """
    driver = _Driver()
    driver._warn_unsupported_options(
        {'configure_bonding_interfaces': True, 'configure_vlan_interfaces': True}
    )

    assert len(driver.said) == 2
    assert any('bonding' in message for message in driver.said)
    assert any('VLAN' in message for message in driver.said)


def test_a_setting_left_at_its_default_says_nothing():
    driver = _Driver()
    driver._warn_unsupported_options(
        {'configure_bonding_interfaces': False, 'configure_vlan_interfaces': False}
    )

    assert driver.said == []
