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

"""Every method the GUI calls on a panel or on the core has to exist.

A name that does not exist raises ``AttributeError`` at the moment the
user triggers the action and nowhere earlier: PySide6 swallows nothing
here, but nothing calls the code either until somebody opens the menu
entry.  ``File > Import Library`` shipped with four such calls at once -
one on the object tree (issue #150) and three on the database manager and
the YAML reader behind it - and nothing in the suite could see any of
them.  This walks the GUI source for the attributes it reads off each of
those objects and asks the class whether it has them.
"""

import ast
import pathlib

import pytest

SRC = pathlib.Path(__file__).resolve().parents[1] / 'src' / 'firewallfabrik'
GUI_DIR = SRC / 'gui'

# Attribute on FWWindow -> the class it holds.
PANELS = {
    '_object_tree': ('object_tree', 'ObjectTree'),
    '_find_panel': ('find_panel', 'FindPanel'),
    '_where_used_panel': ('find_where_used_panel', 'FindWhereUsedPanel'),
}

# Variable name the GUI uses -> the core class behind it.  These carry the
# work File > Import Library and File > Export Library do, and none of it
# is reachable from a test that does not open a window.
CORE_OBJECTS = {
    'db_manager': ('core/_database.py', 'DatabaseManager'),
    '_db_manager': ('core/_database.py', 'DatabaseManager'),
    'import_mgr': ('core/_database.py', 'DatabaseManager'),
    'reader': ('core/_yaml_reader.py', 'YamlReader'),
    'writer': ('core/_yaml_writer.py', 'YamlWriter'),
}


def _attributes_provided(path, class_name):
    """Return every attribute *class_name* defines, including instance ones.

    ``hasattr`` on the class answers for methods and for everything Qt
    brings along, but not for the attributes the constructor assigns, so
    those are read out of the source.
    """
    tree = ast.parse(path.read_text(encoding='utf-8'))
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


def _attributes_used(holder, paths):
    """Return every attribute read off ``<holder>`` or ``self.<holder>``."""
    names = set()
    for path in paths:
        tree = ast.parse(path.read_text(encoding='utf-8'))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Attribute):
                continue
            value = node.value
            if (isinstance(value, ast.Name) and value.id == holder) or (
                isinstance(value, ast.Attribute)
                and value.attr == holder
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

    provided = _attributes_provided(GUI_DIR / f'{module_name}.py', class_name)
    missing = sorted(
        name
        for name in _attributes_used(panel_attr, [GUI_DIR / 'main_window.py'])
        if not hasattr(cls, name) and name not in provided
    )
    assert not missing, (
        f'main_window.py calls {missing} on self.{panel_attr}, '
        f'but {class_name} has no such attribute'
    )


@pytest.mark.parametrize('holder', sorted(CORE_OBJECTS))
def test_the_gui_only_calls_core_methods_that_exist(holder):
    rel_path, class_name = CORE_OBJECTS[holder]
    module = __import__(
        'firewallfabrik.' + rel_path[:-3].replace('/', '.'), fromlist=[class_name]
    )
    cls = getattr(module, class_name)

    provided = _attributes_provided(SRC / rel_path, class_name)
    missing = sorted(
        name
        for name in _attributes_used(holder, sorted(GUI_DIR.rglob('*.py')))
        if not hasattr(cls, name) and name not in provided
    )
    assert not missing, (
        f'the GUI calls {missing} on a {class_name} named {holder!r}, '
        f'but {class_name} has no such attribute'
    )


def _reaches_pyside(module_name, _seen=None):
    """Does ``firewallfabrik.gui.<module_name>`` import PySide6, directly or not?

    Two of the GUI modules are plain Python and a test may import them
    without the extra: ``netmask`` and ``interface_autoconfigure`` do string
    and address work and touch no widget.  Everything else arrives at Qt
    within a hop or two - ``object_tree_data`` imports ``platform_settings``,
    which imports ``QSettings`` - so the question has to follow the imports
    rather than stop at the name.
    """
    if _seen is None:
        _seen = set()
    if module_name in _seen:
        return False
    _seen.add(module_name)
    path = GUI_DIR / f'{module_name}.py'
    if not path.is_file():
        # A package or a name we cannot resolve: assume it reaches Qt.
        return True
    tree = ast.parse(path.read_text(encoding='utf-8'))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or '']
        else:
            continue
        for name in names:
            if name == 'PySide6' or name.startswith('PySide6.'):
                return True
            if name.startswith('firewallfabrik.gui.') and _reaches_pyside(
                name.rsplit('.', 1)[1], _seen
            ):
                return True
    return False


def _module_level_gui_import(tree):
    """Line of the first module-level import that reaches PySide6, or None.

    An import inside a function or a fixture is not counted, because it
    runs after collection and pytest reports it as a failure of that one
    test rather than of the whole run.
    """
    for node in tree.body:
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or '']
        else:
            continue
        for name in names:
            if name == 'PySide6' or name.startswith('PySide6.'):
                return node.lineno
            if name.startswith('firewallfabrik.gui.') and _reaches_pyside(
                name.rsplit('.', 1)[1]
            ):
                return node.lineno
    return None


def _importorskip_line(tree):
    """Line of the module-level ``pytest.importorskip`` call, or None."""
    for node in tree.body:
        if (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and node.value.func.attr == 'importorskip'
        ):
            return node.lineno
    return None


@pytest.mark.parametrize(
    'path',
    sorted(pathlib.Path(__file__).parent.glob('test_*.py')),
    ids=lambda path: path.name,
)
def test_a_gui_test_module_skips_itself_without_the_extra(path):
    """A test module that imports the GUI has to say so before it does.

    The GUI is an optional extra and the CI installs the package without
    it, so a module-level ``from firewallfabrik.gui... import ...`` raises
    ``ModuleNotFoundError`` during collection.  pytest counts that as an
    error and not as a skip, and one such module stops the whole run -
    which is how two of them turned the suite red on every Python version
    at once.  ``pytest.importorskip('PySide6')`` ahead of the import turns
    it into a skip.
    """
    tree = ast.parse(path.read_text(encoding='utf-8'))
    gui_import = _module_level_gui_import(tree)
    if gui_import is None:
        pytest.skip('imports nothing from the GUI at module level')
    guard = _importorskip_line(tree)
    assert guard is not None and guard < gui_import, (
        f'{path.name} imports the GUI on line {gui_import} without a '
        f"pytest.importorskip('PySide6') in front of it, so the module "
        f'fails to collect when the GUI extra is not installed'
    )
