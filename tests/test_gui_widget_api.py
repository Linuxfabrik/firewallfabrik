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

"""Every method the main window calls on a panel has to exist on it.

A name that does not exist raises ``AttributeError`` at the moment the
user triggers the action and nowhere earlier: PySide6 swallows nothing
here, but nothing calls the code either until somebody opens the menu
entry.  ``File > Import Library`` shipped with a call to a method the
object tree never had (issue #150).  This walks the main window's source
for the attributes it reads off each panel and asks the class whether it
has them.
"""

import ast
import pathlib

import pytest

GUI_DIR = pathlib.Path(__file__).resolve().parents[1] / 'src' / 'firewallfabrik' / 'gui'

# Attribute on FWWindow -> the class it holds.
PANELS = {
    '_object_tree': ('object_tree', 'ObjectTree'),
    '_find_panel': ('find_panel', 'FindPanel'),
    '_where_used_panel': ('find_where_used_panel', 'FindWhereUsedPanel'),
}


def _attributes_provided(module_name, class_name):
    """Return every attribute *class_name* defines, including instance ones.

    ``hasattr`` on the class answers for methods and for everything Qt
    brings along, but not for the attributes the constructor assigns, so
    those are read out of the source.
    """
    tree = ast.parse((GUI_DIR / f'{module_name}.py').read_text(encoding='utf-8'))
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            names = set()
            for inner in ast.walk(node):
                if (
                    isinstance(inner, ast.Attribute)
                    and isinstance(inner.ctx, ast.Store)
                    and isinstance(inner.value, ast.Name)
                    and inner.value.id == 'self'
                ):
                    names.add(inner.attr)
            return names
    return set()


def _attributes_used(panel_attr):
    """Return every attribute name read off ``self.<panel_attr>``."""
    tree = ast.parse((GUI_DIR / 'main_window.py').read_text(encoding='utf-8'))
    names = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute):
            continue
        value = node.value
        if (
            isinstance(value, ast.Attribute)
            and value.attr == panel_attr
            and isinstance(value.value, ast.Name)
            and value.value.id == 'self'
        ):
            names.add(node.attr)
    return names


@pytest.mark.parametrize('panel_attr', sorted(PANELS))
def test_main_window_only_calls_methods_that_exist(panel_attr):
    module_name, class_name = PANELS[panel_attr]
    pytest.importorskip('PySide6')
    module = __import__(f'firewallfabrik.gui.{module_name}', fromlist=[class_name])
    cls = getattr(module, class_name)

    provided = _attributes_provided(module_name, class_name)
    missing = sorted(
        name
        for name in _attributes_used(panel_attr)
        if not hasattr(cls, name) and name not in provided
    )
    assert not missing, (
        f'main_window.py calls {missing} on self.{panel_attr}, '
        f'but {class_name} has no such attribute'
    )
