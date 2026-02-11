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

"""Label definitions and QSettings helpers for rule color labels."""

from PySide6.QtCore import QSettings

# 7 label slots with Solarized-based defaults.
LABEL_DEFAULTS = {
    'color1': {'color': '#fdf6e3', 'text': 'Outbound'},
    'color2': {'color': '#eee8d5', 'text': 'Inbound'},
    'color3': {'color': '#dc322f', 'text': 'Block'},
    'color4': {'color': '#93a1a1', 'text': 'DNAT/Forward'},
    'color5': {'color': '#839496', 'text': 'SNAT/Forward'},
    'color6': {'color': '#A37EC0', 'text': 'Purple'},
    'color7': {'color': '#C0C0C0', 'text': 'Gray'},
}

LABEL_KEYS = sorted(LABEL_DEFAULTS)


def get_label_color(key):
    """Return the hex color string for the given label key."""
    default = LABEL_DEFAULTS.get(key, {}).get('color', '#FFFFFF')
    return QSettings().value(f'Labels/color_{key}', default, type=str)


def get_label_text(key):
    """Return the display text for the given label key."""
    default = LABEL_DEFAULTS.get(key, {}).get('text', key)
    return QSettings().value(f'Labels/text_{key}', default, type=str)


def set_label_color(key, hex_color):
    """Persist the hex color string for the given label key."""
    QSettings().setValue(f'Labels/color_{key}', hex_color)


def set_label_text(key, text):
    """Persist the display text for the given label key."""
    QSettings().setValue(f'Labels/text_{key}', text)
