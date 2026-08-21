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

"""Which chain decisions stop recognising a broadcast on a bridging firewall.

A broadcast or a multicast frame is delivered locally on an ordinary
firewall and never routed, which is why ``complex_match`` counts one as
"the firewall".  A *bridging* firewall forwards it, so two of the chain
decisions have to ask the plain question there.  Firewall Builder writes
that as ``b=m= !( getCachedFwOpt()->getBool("bridging_fw") )`` and it is
live in exactly four places - ``finalizeChain`` (twice) and
``splitIf{Src,Dst}MatchingAddressRange``.

The same line sits in ``decideOnChainIf{Src,Dst}FW`` as well and is
**commented out** there, with the reason spelled out above it: since
fwbuilder's bug #811860 the rule is split into INPUT and FORWARD by
``bridgingFw``, which runs after ``finalizeChain``, so the decision itself
no longer has to hold back.  Reading that comment as code takes the input
copy away from a bridging firewall - the reference output for firewall11
carries both lines for its OSPF and VRRP multicast rules.

This is a source-level guard because no firewall of the test corpus
reaches the four call sites with such an object: on firewall11 the chain
is already decided by the time ``finalizeChain`` sees the rule.  The
question the processors ask is what the guard pins.
"""

import ast
import pathlib

import pytest

_PLATFORM_DIR = (
    pathlib.Path(__file__).resolve().parents[1] / 'src' / 'firewallfabrik' / 'platforms'
)

_POLICY_COMPILERS = (
    _PLATFORM_DIR / 'iptables' / '_policy_compiler.py',
    _PLATFORM_DIR / 'nftables' / '_policy_compiler.py',
)

# The processors whose C++ counterpart computes the two flags from
# `bridging_fw`, and the ones whose counterpart deliberately does not.
_ASKS_WITHOUT_BROADCASTS = (
    'FinalizeChain',
    'SplitIfSrcMatchingAddressRange',
    'SplitIfDstMatchingAddressRange',
)
_ASKS_WITH_BROADCASTS = (
    'DecideOnChainIfSrcFW',
    'DecideOnChainIfDstFW',
)


def _flag_arguments(path, class_name):
    """Return the flag pairs every complex_match call in *class_name* passes.

    Each entry is ``(broadcasts, multicasts)`` as source text, or ``None``
    where the call names neither - which means the default, and the
    default is "recognise them".
    """
    tree = ast.parse(path.read_text())
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef) or node.name != class_name:
            continue
        for call in ast.walk(node):
            if not isinstance(call, ast.Call):
                continue
            if not isinstance(call.func, ast.Attribute):
                continue
            if call.func.attr != 'complex_match':
                continue
            keywords = {k.arg: ast.unparse(k.value) for k in call.keywords}
            if keywords:
                found.append(
                    (
                        keywords.get('recognize_broadcasts'),
                        keywords.get('recognize_multicasts'),
                    ),
                )
            elif len(call.args) > 3:
                # complex_match(obj, fw, recognize_broadcasts, recognize_multicasts)
                found.append((ast.unparse(call.args[2]), ast.unparse(call.args[3])))
            else:
                found.append(None)
    return found


@pytest.mark.parametrize('path', _POLICY_COMPILERS, ids=lambda p: p.parent.name)
@pytest.mark.parametrize('class_name', _ASKS_WITHOUT_BROADCASTS)
def test_a_bridging_firewall_forwards_the_frame(path, class_name):
    flags = _flag_arguments(path, class_name)
    assert flags, f'{class_name} in {path.name} asks complex_match nothing'
    for pair in flags:
        assert pair == ('not bridging', 'not bridging'), (
            f'{class_name} in {path.name} asks with {pair}; fwbuilder computes '
            'both flags from bridging_fw there'
        )


@pytest.mark.parametrize('path', _POLICY_COMPILERS, ids=lambda p: p.parent.name)
@pytest.mark.parametrize('class_name', _ASKS_WITH_BROADCASTS)
def test_the_chain_decision_still_recognises_them(path, class_name):
    """The `!bridging_fw` line is commented out in the C++ here.

    ``bridgingFw`` adds the forward copy after ``finalizeChain``, so the
    decision itself keeps recognising a broadcast; asking otherwise costs
    the input copy of every such rule on a bridging firewall.
    """
    flags = _flag_arguments(path, class_name)
    assert flags, f'{class_name} in {path.name} asks complex_match nothing'
    for pair in flags:
        assert pair in (None, ('True', 'True'), ('False', 'False')), (
            f'{class_name} in {path.name} asks with {pair}'
        )
