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

"""The default of a firewall option lives in `defaults.yaml` and nowhere else.

`docs/developer-guide/PlatformDefaults.md` says so, and it matters where
a data file does not carry the key: a driver reading the raw dict with a
fallback of its own answers the question its own way, and a `true` in the
schema then never applies.  The two platforms have to agree as well - the
same option means the same thing on both, and a firewall switched from
one to the other must not silently change what the generated script does.
"""

import ast
import pathlib

import pytest
import yaml

SRC = pathlib.Path(__file__).resolve().parent.parent / 'src' / 'firewallfabrik'
DRIVERS = [
    SRC / 'platforms' / 'iptables' / '_compiler_driver.py',
    SRC / 'platforms' / 'nftables' / '_compiler_driver.py',
]


def _schema(platform):
    loaded = yaml.safe_load(
        (SRC / 'platforms' / platform / 'defaults.yaml').read_text()
    )
    return loaded.get('options', loaded)


def _option_get_calls(path):
    """Every ``<dict>.get('key', ...)`` on a variable named ``options``."""
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr != 'get':
            continue
        if not isinstance(func.value, ast.Name) or func.value.id != 'options':
            continue
        if not node.args or not isinstance(node.args[0], ast.Constant):
            continue
        yield node.args[0].value, node.lineno


@pytest.mark.parametrize('driver', DRIVERS, ids=lambda p: p.parent.name)
def test_no_driver_substitutes_its_own_default(driver):
    """A firewall option is read through ``get_option``, which knows the schema."""
    platform = driver.parent.name
    known = set(_schema(platform)) | set(_schema('linux'))
    offenders = [
        f'{driver.name}:{line} reads {key!r} from the raw options dict'
        for key, line in _option_get_calls(driver)
        if key in known
    ]
    assert offenders == []


def test_the_two_platforms_agree_on_every_shared_default():
    """Switching platform must not change what the generated script does."""
    ipt, nft = _schema('iptables'), _schema('nftables')
    differing = {
        key: (ipt[key].get('default'), nft[key].get('default'))
        for key in set(ipt) & set(nft)
        if ipt[key].get('default') != nft[key].get('default')
    }
    assert differing == {}
