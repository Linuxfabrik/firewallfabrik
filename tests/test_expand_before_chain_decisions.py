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

"""The chain decisions have to see addresses, not the objects around them.

Every processor from ``DecideOnChainIfLoopback`` to
``SpecialCaseWithFWInDstAndOutbound`` asks its question of the *first*
object in the source or the destination, and the question is about an
address: is this the firewall, is it a broadcast, is it on a network the
firewall has an interface on.  A Host object holding one address answers
none of them, so Firewall Builder replaces both elements with the
addresses behind them first
(``PolicyCompiler_ipt.cpp:4566``, before ``finalizeChain``).

The order is what this pins, because getting it wrong costs whole rules
without a word: with the expansion behind the chain decisions, the
outbound half of a rule whose destination is the ``broadcast`` host object
was dropped on a bridging firewall, on both platforms - two rules of
firewall11 in the Firewall Builder reference output.
"""

import ast
import pathlib

import pytest

_PLATFORM_DIR = (
    pathlib.Path(__file__).resolve().parents[1] / 'src' / 'firewallfabrik' / 'platforms'
)

_POLICY_COMPILERS = {
    'iptables': _PLATFORM_DIR / 'iptables' / '_policy_compiler.py',
    'nftables': _PLATFORM_DIR / 'nftables' / '_policy_compiler.py',
}

#: Added to the pipeline before any chain is decided.
_EXPANSIONS = (
    'ExpandMultipleAddressesIfNotFWInSrc',
    'ExpandMultipleAddressesIfNotFWInDst',
)

#: Every processor that reads src or dst to decide a chain or a target.
_CHAIN_DECISIONS = (
    'DecideOnChainIfLoopback',
    'FinalizeChain',
    'SpecialCaseWithFWInDstAndOutbound',
    'DecideOnTarget',
)


def _pipeline_order(path):
    """Return the processor class names ``compile()`` adds, in order."""
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or node.name != 'compile':
            continue
        names = []
        for call in ast.walk(node):
            if not isinstance(call, ast.Call):
                continue
            func = call.func
            if not (isinstance(func, ast.Attribute) and func.attr == 'add'):
                continue
            for arg in call.args:
                if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name):
                    names.append(arg.func.id)
        if names:
            return names
    raise AssertionError(f'no compile() with a pipeline in {path}')


@pytest.mark.parametrize('platform', sorted(_POLICY_COMPILERS))
def test_addresses_are_expanded_before_the_chain_is_decided(platform):
    order = _pipeline_order(_POLICY_COMPILERS[platform])

    last_expansion = max(
        (order.index(name) for name in _EXPANSIONS if name in order), default=-1
    )
    assert last_expansion >= 0, (
        f'the {platform} policy pipeline does not expand src and dst before '
        f'deciding a chain; Firewall Builder does '
        f'(PolicyCompiler_ipt.cpp:4566)'
    )

    for name in _CHAIN_DECISIONS:
        assert name in order, f'{name} is missing from the {platform} pipeline'
        assert order.index(name) > last_expansion, (
            f'{name} runs before the addresses are expanded on {platform}, so '
            f'it reads a Host or an Interface object where it expects an '
            f'address'
        )


@pytest.mark.parametrize('platform', sorted(_POLICY_COMPILERS))
def test_a_rule_the_expansion_emptied_is_dropped_before_the_chain(platform):
    """An emptied element is not "any", so it must not reach a chain decision."""
    order = _pipeline_order(_POLICY_COMPILERS[platform])
    last_expansion = max(
        (order.index(name) for name in _EXPANSIONS if name in order), default=-1
    )
    assert last_expansion >= 0, (
        f'the {platform} policy pipeline does not expand src and dst at all'
    )
    drops = [i for i, name in enumerate(order) if name == 'DropRuleWithEmptyRE']
    assert any(last_expansion < i < order.index('FinalizeChain') for i in drops), (
        f'the {platform} pipeline decides a chain for a rule whose source or '
        f'destination the expansion emptied; Firewall Builder drops it right '
        f'after the expansion'
    )
