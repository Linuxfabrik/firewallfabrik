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

"""The parameters of the protocol a cluster group speaks.

Ports fwbuilder's ``vrrpOptionsDialog``, ``heartbeatOptionsDialog``,
``openaisOptionsDialog`` and ``conntrackOptionsDialog``, which the
"Edit Parameters" button of the cluster group editor opens.

These are not decoration.  The compiler writes the rules that let a
member see the other members out of exactly these values
(``platforms/linux/_automatic_rules.py``): the address and the port
decide which packets the rule permits, and the unicast flag decides
whether the rule names a multicast group at all or the other members'
interfaces.  Without the dialogs the values were stuck at whatever the
data file happened to carry, and a cluster that replicates on a port of
its own had its state sync traffic dropped by its own policy.

Every value lives on the *group's* options dict, the way
``FWOptions::cast(obj)`` reads it in the C++.
"""

from pathlib import Path

from PySide6.QtCore import QByteArray, QSettings
from PySide6.QtWidgets import QDialog

from firewallfabrik.gui.ui_loader import FWFUiLoader

_UI_DIR = Path(__file__).resolve().parent / 'ui'


class _ClusterProtocolDialog(QDialog):
    """One protocol's parameters, read from and written to a group.

    Subclasses name their ``.ui`` file and the option keys behind their
    widgets.  Nothing else differs between the four.
    """

    #: The ``.ui`` file, relative to the ui directory.
    ui_file = ''
    #: ``{widget name: option key}``.  The widget type decides how the
    #: value is read: a check box gives a bool, a spin box an int and a
    #: line edit the text as typed.
    widget_options: dict[str, str] = {}  # noqa: RUF012

    def __init__(self, options=None, parent=None):
        super().__init__(parent)
        loader = FWFUiLoader(self)
        loader.load(str(_UI_DIR / self.ui_file))
        self._options = dict(options or {})
        self._populate()
        self._restore_geometry()

    def get_options(self):
        """Return the group's options with this dialog's values merged in."""
        result = dict(self._options)
        for widget_name, key in self.widget_options.items():
            widget = getattr(self, widget_name)
            if hasattr(widget, 'isChecked'):
                result[key] = widget.isChecked()
            elif hasattr(widget, 'value'):
                result[key] = str(widget.value())
            else:
                result[key] = widget.text().strip()
        return result

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _populate(self):
        for widget_name, key in self.widget_options.items():
            widget = getattr(self, widget_name)
            stored = self._options.get(key)
            if hasattr(widget, 'setChecked'):
                widget.setChecked(_as_bool(stored))
            elif hasattr(widget, 'setValue'):
                # An empty or unreadable value leaves the spin box at the
                # default the .ui file carries, which is the protocol's
                # own port - the same value the compiler falls back to.
                number = _as_int(stored)
                if number is not None:
                    widget.setValue(
                        max(widget.minimum(), min(widget.maximum(), number))
                    )
            else:
                widget.setText('' if stored is None else str(stored))

    def _restore_geometry(self):
        """Restore the saved position, or centre on the parent window."""
        settings = QSettings()
        geometry = settings.value(self._geometry_key(), type=QByteArray)
        if geometry and self.restoreGeometry(geometry):
            return
        parent = self.parentWidget()
        if parent is not None:
            geo = self.geometry()
            geo.moveCenter(parent.window().geometry().center())
            self.setGeometry(geo)

    def _geometry_key(self):
        return f'{type(self).__name__}/geometry'

    def done(self, result):
        QSettings().setValue(self._geometry_key(), self.saveGeometry())
        super().done(result)


def _as_bool(value):
    """Read a stored flag the way ``FWObject::getBool`` does."""
    from firewallfabrik.core._options import option_is_true

    return option_is_true(value)


def _as_int(value):
    """The number *value* holds, or ``None`` when it holds none.

    A data file written by another tool may carry anything here, and a
    spin box cannot show a word.  ``None`` leaves the default in place
    rather than showing 0, which is not a port.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text.isdigit():
        return None
    return int(text)


class VRRPOptionsDialog(_ClusterProtocolDialog):
    """VRRP: the advertisement protocol, the shared secret and the VRID."""

    ui_file = 'vrrpoptionsdialog_q.ui'
    widget_options = {  # noqa: RUF012
        'vrrp_over_ipsec_ah': 'vrrp_over_ipsec_ah',
        'vrrp_secret': 'vrrp_secret',  # nosec B105 - an option key, not a password
        'vrrp_vrid': 'vrrp_vrid',
    }


class HeartbeatOptionsDialog(_ClusterProtocolDialog):
    """heartbeat: the multicast group and port from ``ha.cf``."""

    ui_file = 'heartbeatoptionsdialog_q.ui'
    widget_options = {  # noqa: RUF012
        'use_unicast': 'heartbeat_unicast',
        'heartbeat_address': 'heartbeat_address',
        'heartbeat_port': 'heartbeat_port',
    }


class OpenAISOptionsDialog(_ClusterProtocolDialog):
    """OpenAIS / corosync: the totem ring's multicast group and port."""

    ui_file = 'openaisoptionsdialog_q.ui'
    widget_options = {  # noqa: RUF012
        'openais_address': 'openais_address',
        'openais_port': 'openais_port',
    }


class ConntrackOptionsDialog(_ClusterProtocolDialog):
    """conntrackd: where and how the connection table is replicated."""

    ui_file = 'conntrackoptionsdialog_q.ui'
    widget_options = {  # noqa: RUF012
        'use_unicast': 'conntrack_unicast',
        'conntrack_address': 'conntrack_address',
        'conntrack_port': 'conntrack_port',
    }


#: Which dialog edits which protocol.  A group whose protocol is not in
#: here has no parameters to edit, which is what "none" means.
PROTOCOL_DIALOGS = {
    'conntrack': ConntrackOptionsDialog,
    'heartbeat': HeartbeatOptionsDialog,
    'openais': OpenAISOptionsDialog,
    'vrrp': VRRPOptionsDialog,
}
