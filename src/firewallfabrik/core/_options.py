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

"""How a stored option value becomes a boolean.

An option is a string in the data file, and a data file may put that
string on a line of its own::

    <Option name="mangle_only_rule_set">
      True
    </Option>

Firewall Builder writes both shapes and reads them the same way: its XML
reader keeps the content verbatim (``FWOptions::fromXML``) and
``FWObject::getBool`` removes *every* space, tab and newline before it
compares (libfwbuilder/src/fwbuilder/FWObject.cpp, with the date of the
fix in a comment above it).  ``getStr`` does not, which is why the
removal belongs here and not in the reader: a log prefix ends in a space
on purpose and a shell prompt is nothing but spaces.
"""


def option_is_true(value) -> bool:
    """Is *value* the stored spelling of "yes"?

    Accepts ``True``, ``1`` and any capitalisation of ``true``, in the
    line-wrapped form as well.  Everything else, ``None`` and the empty
    string included, is False.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value == 1
    if value is None:
        return False
    return _collapse(value) in ('1', 'true')


def option_bool(value, default=None):
    """Return ``True`` / ``False`` for a stored boolean, else *default*.

    Used where a value may legitimately be something other than a
    boolean - an option dict holds strings, numbers and booleans side by
    side - so a non-boolean has to come back untouched rather than as
    ``False``.
    """
    if isinstance(value, bool):
        return value
    if not isinstance(value, str):
        return default
    collapsed = _collapse(value)
    if collapsed == 'true':
        return True
    if collapsed == 'false':
        return False
    return default


def option_int(value, default: int = 0) -> int:
    """The number a stored option reads as, the way ``FWObject::getInt`` does.

    That accessor runs the stored string through ``atoi``, so it takes the
    leading integer and answers 0 for anything that does not start with
    one - ``"true"`` included, which is why an option written that way is
    off wherever Firewall Builder reads it as a number.  A stored bool or
    int comes back as itself.
    """
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if value is None:
        return default
    text = _collapse(value)
    sign = 1
    if text[:1] in ('+', '-'):
        sign = -1 if text[0] == '-' else 1
        text = text[1:]
    digits = ''
    for char in text:
        if not char.isdigit():
            break
        digits += char
    return sign * int(digits) if digits else 0


def _collapse(value) -> str:
    """Lower-case *value* with every whitespace character removed."""
    return ''.join(str(value).split()).lower()
