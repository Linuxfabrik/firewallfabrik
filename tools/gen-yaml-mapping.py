#!/usr/bin/env python3
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

"""Generate the GUI-to-YAML mapping tables for the user guide.

The firewall settings exposed in the GUI are stored verbatim under a
Firewall object's ``options:`` map in the ``.fwf`` file. The single
source of truth for every option key, its type, default value, GUI
widget and human-readable description is the set of ``defaults.yaml``
files shipped with each platform/OS package:

    src/firewallfabrik/platforms/linux/defaults.yaml      (Host OS settings)
    src/firewallfabrik/platforms/iptables/defaults.yaml   (Platform settings)
    src/firewallfabrik/platforms/nftables/defaults.yaml   (Platform settings)

The human-readable field labels and the tab they live on are read from
the matching Qt ``.ui`` files.

This script renders Markdown tables from those sources and writes them
into the user guide between the marker comments

    <!-- BEGIN GENERATED firewall-options-mapping -->
    <!-- END GENERATED firewall-options-mapping -->

Re-run it whenever a ``defaults.yaml`` or settings dialog changes to keep
the documentation in sync. It never touches anything outside the markers.
"""

import sys
import xml.etree.ElementTree as ET  # nosec B405 -- trusted, in-repo .ui files
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
PLATFORMS = REPO_ROOT / 'src' / 'firewallfabrik' / 'platforms'
UI_DIR = REPO_ROOT / 'src' / 'firewallfabrik' / 'gui' / 'ui'
DOC = REPO_ROOT / 'docs' / 'user-guide' / '16 - Appendix.md'

MARKER_BEGIN = '<!-- BEGIN GENERATED firewall-options-mapping -->'
MARKER_END = '<!-- END GENERATED firewall-options-mapping -->'

# Input widget classes whose value maps to an option key.
INPUT_CLASSES = {
    'QCheckBox',
    'QComboBox',
    'QLineEdit',
    'QPlainTextEdit',
    'QRadioButton',
    'QSpinBox',
    'QTextEdit',
}

# Human-readable type description for the "Type / values" column.
TYPE_LABELS = {
    'bool': 'on/off (`true` / `false`)',
    'tristate': "tri-state (`''` no change, `'1'` on, `'0'` off)",
    'int': 'integer (`-1` = kernel default)',
    'str': 'string',
    'text': 'multi-line string',
}


def _text(widget):
    """Return the immediate ``text`` property string of a widget, or ''."""
    for prop in widget.findall('property'):
        if prop.get('name') == 'text':
            s = prop.find('string')
            if s is not None and s.text:
                return ' '.join(s.text.split())
    return ''


def _nearest_row_label(by_row, row):
    """Label on the row directly above (preferred) or below ``row``."""
    if row is None:
        return ''
    try:
        r = int(row)
    except (TypeError, ValueError):
        return ''
    for candidate in (r - 1, r + 1):
        text = by_row.get(str(candidate))
        if text:
            return text
    return ''


def index_ui(ui_path):
    """Build lookup tables from a Qt .ui file.

    Returns a tuple of three dicts:

    - ``labels``  : QLabel objectName  -> label text
    - ``widgets`` : input objectName   -> {'text': own text, 'tab': tab title}
    - ``row_label``: input objectName  -> text of a sibling QLabel on the same
                     grid row (fallback when the widget carries no own text)
    - ``prev_label``: input objectName -> text of the QLabel on an adjacent
                     grid row (fallback for label-above-field layouts)
    """
    # The .ui files are trusted, version-controlled project resources.
    tree = ET.parse(ui_path)  # nosec B314
    labels = {}
    widgets = {}
    row_label = {}
    # prev_label holds the nearest preceding QLabel within the *same layout*
    # (handles the common "label on the row above the field" arrangement).
    prev_label = {}

    def walk(elem, tab):
        # A QTabWidget page carries its tab name in an <attribute name="title">.
        for attr in elem.findall('attribute'):
            if attr.get('name') == 'title':
                s = attr.find('string')
                if s is not None and s.text:
                    tab = s.text.strip()

        if elem.tag == 'layout':
            items = elem.findall('item')
            # First pass: remember the QLabel text per grid row.
            by_row = {}
            for it in items:
                w = it.find('widget')
                if w is not None and w.get('class') == 'QLabel':
                    by_row[it.get('row')] = _text(w)
            # Second pass: record input widgets and recurse.
            for it in items:
                w = it.find('widget')
                if w is not None:
                    name = w.get('name')
                    cls = w.get('class')
                    if cls == 'QLabel' and name:
                        labels[name] = _text(w)
                    elif cls in INPUT_CLASSES and name:
                        widgets[name] = {'text': _text(w), 'tab': tab}
                        row = it.get('row')
                        if by_row.get(row):
                            row_label[name] = by_row[row]
                        else:
                            # Fall back to the label on the adjacent grid row
                            # (label-above-field, the most common form layout).
                            near = _nearest_row_label(by_row, row)
                            if near:
                                prev_label[name] = near
                    walk(w, tab)
                nested = it.find('layout')
                if nested is not None:
                    walk(nested, tab)
            return

        for child in elem:
            walk(child, tab)

    walk(tree.getroot(), '')
    return labels, widgets, row_label, prev_label


def resolve_label(opt, ui_index):
    """Best-effort human label for an option, using its defaults + .ui data."""
    labels, widgets, row_label, prev_label = ui_index
    widget = opt.get('widget')
    # 1. Explicit label objectName from defaults.yaml (combos, line edits).
    label_name = opt.get('label')
    if label_name and labels.get(label_name):
        return labels[label_name]
    # 2. The widget's own text (check boxes, radio buttons).
    if widget and widgets.get(widget, {}).get('text'):
        return widgets[widget]['text']
    # 3. A sibling QLabel on the same grid row.
    if widget and row_label.get(widget):
        return row_label[widget]
    # 4. The nearest preceding QLabel in document order (label-above-field).
    if widget and prev_label.get(widget):
        return prev_label[widget]
    return ''


def load_options(pkg):
    data = yaml.safe_load((PLATFORMS / pkg / 'defaults.yaml').read_text())
    return data.get('options', {})


def fmt_type(opt):
    if opt.get('type') == 'enum':
        values = opt.get('values', [])
        joined = ', '.join(f'`{v}`' for v in values)
        return f'one of: {joined}' if joined else 'enum'
    return TYPE_LABELS.get(opt.get('type'), opt.get('type', ''))


def fmt_default(opt):
    default = opt.get('default')
    if opt.get('type') == 'bool':
        return f'`{str(bool(default)).lower()}`'
    if default is None or default == '':
        return "`''`"
    return f'`{default}`'


def table(rows, header):
    out = ['| ' + ' | '.join(header) + ' |']
    out.append('|' + '|'.join(['---'] * len(header)) + '|')
    for row in rows:
        cells = [str(c).replace('|', '\\|') for c in row]
        out.append('| ' + ' | '.join(cells) + ' |')
    return '\n'.join(out)


def build_host_os_table():
    options = load_options('linux')
    ui_index = index_ui(UI_DIR / 'linuxsettingsdialog_q.ui')
    widgets = ui_index[1]
    rows = []
    for key in sorted(options):
        opt = options[key]
        # Skip options that are inactive or have no GUI representation.
        if not opt.get('supported', True) or opt.get('widget') is None:
            continue
        tab = widgets.get(opt.get('widget'), {}).get('tab', '')
        label = resolve_label(opt, ui_index) or key
        avail = ['iptables']
        if opt.get('nftables_supported', True):
            avail.append('nftables')
        rows.append(
            [
                tab,
                label,
                f'`{key}`',
                fmt_type(opt),
                fmt_default(opt),
                ', '.join(avail),
            ]
        )
    header = [
        'Tab',
        'GUI field',
        'YAML key (under `options:`)',
        'Type / values',
        'Default',
        'Platform',
    ]
    return table(rows, header)


def build_platform_table():
    ipt = load_options('iptables')
    nft = load_options('nftables')
    ipt_ui = index_ui(UI_DIR / 'iptablessettingsdialog_q.ui')
    nft_ui = index_ui(UI_DIR / 'nftablessettingsdialog_q.ui')
    rows = []
    for key in sorted(set(ipt) | set(nft)):
        avail = []
        if key in ipt and ipt[key].get('supported', True):
            avail.append('iptables')
        if key in nft and nft[key].get('supported', True):
            avail.append('nftables')
        if not avail:
            # Inactive on every platform: nothing the admin can set here.
            continue
        opt = ipt.get(key) or nft[key]
        ui_index = ipt_ui if key in ipt else nft_ui
        widgets = ui_index[1]
        if opt.get('widget') is None:
            continue
        tab = widgets.get(opt.get('widget'), {}).get('tab', '')
        label = resolve_label(opt, ui_index) or key
        rows.append(
            [
                tab,
                label,
                f'`{key}`',
                fmt_type(opt),
                fmt_default(opt),
                ', '.join(avail),
            ]
        )
    header = [
        'Tab',
        'GUI field',
        'YAML key (under `options:`)',
        'Type / values',
        'Default',
        'Platform',
    ]
    return table(rows, header)


def render():
    parts = []
    parts.append('### Host OS settings (Firewall > Host OS Settings ...)\n')
    parts.append(build_host_os_table())
    parts.append('\n\n### Platform settings (Firewall > Platform Settings ...)\n')
    parts.append(build_platform_table())
    return '\n'.join(parts)


def main():
    generated = render()
    text = DOC.read_text()
    if MARKER_BEGIN not in text or MARKER_END not in text:
        sys.exit(
            f'error: markers not found in {DOC}. Add:\n  {MARKER_BEGIN}\n  {MARKER_END}'
        )
    head = text.split(MARKER_BEGIN)[0]
    tail = text.split(MARKER_END)[1]
    new = f'{head}{MARKER_BEGIN}\n\n{generated}\n\n{MARKER_END}{tail}'
    DOC.write_text(new)
    print(f'wrote mapping tables to {DOC}')


if __name__ == '__main__':
    main()
