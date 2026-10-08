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

"""Editor panel dialogs for device objects (Host, Firewall, Interface)."""

from datetime import UTC, datetime

from PySide6.QtCore import QSettings, Qt, Slot
from PySide6.QtWidgets import QDialog

from firewallfabrik.gui.base_object_dialog import BaseObjectDialog
from firewallfabrik.gui.iptables_settings_dialog import IptablesSettingsDialog
from firewallfabrik.gui.linux_settings_dialog import LinuxSettingsDialog
from firewallfabrik.gui.nftables_settings_dialog import NftablesSettingsDialog
from firewallfabrik.gui.platform_settings import (
    HOST_OS,
    PLATFORMS,
    get_enabled_os,
    get_enabled_platforms,
    get_unset_version_label,
    get_versions_for_platform,
)


def _set_data_key(data: dict, key: str, value, default=None) -> None:
    """Set *key* in *data* only if it already exists or *value* differs from *default*.

    This avoids injecting new keys with default values into the data
    dict, which would cause the ORM to detect a change and bump
    ``lastModified`` even when the user didn't change anything.
    """
    if key in data or value != default:
        data[key] = value


# Reverse mapping: display name → internal key for host OS.
_HOST_OS_INTERNAL = {v: k for k, v in HOST_OS.items()}

# The same for the platform, so the release list can be looked up from
# what the platform combo shows.
_PLATFORM_INTERNAL = {v: k for k, v in PLATFORMS.items()}

# Platform display name → settings dialog class.
_PLATFORM_SETTINGS_DIALOG = {
    'iptables': IptablesSettingsDialog,
    'nftables': NftablesSettingsDialog,
}


def _autoconfigure_interfaces():
    """The "autoconfigure interfaces" preference, on unless switched off."""
    from PySide6.QtCore import QSettings

    return QSettings().value(
        'Objects/Interface/autoconfigureInterfaces', True, type=bool
    )


class HostDialog(BaseObjectDialog):
    def __init__(self, parent=None):
        super().__init__('hostdialog_q.ui', parent)

    def _populate(self):
        self.obj_name.setText(self._obj.name or '')
        self.MACmatching.setChecked(self._obj.matches_by_mac())

    def _apply_changes(self):
        new_name = self.obj_name.text()
        if self._obj.name != new_name:
            self._obj.name = new_name
        checked = self.MACmatching.isChecked()
        if checked != self._obj.matches_by_mac():
            self._obj.set_matches_by_mac(checked)


class FirewallDialog(BaseObjectDialog):
    def __init__(self, parent=None):
        super().__init__('firewalldialog_q.ui', parent)
        # Connected once here: _populate runs for every object shown.  A
        # cluster's panel has no release, and no button to look one up.
        lookup = getattr(self, 'lookupVersion', None)
        if lookup is not None:
            lookup.clicked.connect(self._lookup_version)

    def _lookup_version(self):
        """Ask the firewall which releases it runs and offer the entry.

        It logs in the way the installer does (see `version_lookup`), and
        asks for a password only when the key or the agent is not enough.
        Nothing is changed until the administrator accepts the entry.
        """
        from PySide6.QtWidgets import QApplication, QInputDialog, QLineEdit, QMessageBox

        from firewallfabrik.gui import version_lookup
        from firewallfabrik.platforms import _versions

        platform = _PLATFORM_INTERNAL.get(self.platform.currentText(), '')
        options = self._obj.options or {}
        settings = QSettings()
        ask = {
            'address': version_lookup.resolve_mgmt_address(self._obj),
            'user': options.get('admUser', '') or 'root',
            'extra_args': options.get('sshArgs', ''),
            'ssh_path': settings.value('SSH/SSHPath', '', type=str),
            'timeout': settings.value('SSH/SSHTimeout', 10, type=int) or 10,
        }
        title = 'Lookup Version'
        result = None
        # Empty until ssh asks for one; not a password of any kind.
        password = ''  # nosec B105
        while result is None:
            QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
            try:
                result = version_lookup.run(password=password, **ask)
            except version_lookup.AuthenticationRequired:
                QApplication.restoreOverrideCursor()
                password, ok = QInputDialog.getText(
                    self,
                    title,
                    f'Password for {ask["user"]}@{ask["address"]}:',
                    QLineEdit.EchoMode.Password,
                )
                if not ok or not password:
                    return
                continue
            except version_lookup.LookupFailed as exc:
                QApplication.restoreOverrideCursor()
                QMessageBox.warning(
                    self, title, f'The firewall could not be asked: {exc}'
                )
                return
            QApplication.restoreOverrideCursor()

        release = result.nftables if platform == 'nftables' else result.iptables
        facts = (
            f'{result.distribution or "unknown distribution"}, '
            f'kernel {result.kernel or "unknown"}\n'
            f'nftables {result.nftables or "not installed"}\n'
            f'iptables {result.iptables or "not installed"}'
            + (f' ({result.iptables_backend})' if result.iptables_backend else '')
        )
        entry = result.entry(platform)
        if not entry:
            QMessageBox.information(
                self,
                title,
                f'{facts}\n\n{platform} is not installed on the firewall, so no '
                'entry fits.',
            )
            return
        if entry == self.version.currentData():
            QMessageBox.information(
                self,
                title,
                f'{facts}\n\nThe entry already chosen fits: '
                f'{_versions.label(platform, entry)}',
            )
            return
        answer = QMessageBox.question(
            self,
            title,
            f'{facts}\n\nThe entry for {platform} {release or ""} on this '
            f'firewall is:\n{_versions.label(platform, entry)}\n\nUse it?',
        )
        if answer == QMessageBox.StandardButton.Yes:
            self.version.setCurrentIndex(self.version.findData(entry))

    def _populate(self):
        self.obj_name.setText(self._obj.name or '')
        data = self._obj.data or {}

        # Populate combos with enabled entries before setting the current value.
        self.platform.clear()
        for display in get_enabled_platforms().values():
            self.platform.addItem(display)
        self.hostOS.clear()
        for display in get_enabled_os().values():
            self.hostOS.addItem(display)

        self._set_combo_text(self.platform, data.get('platform', ''))
        # A cluster has no release of its own, so its panel has no combo
        # for one; everything else on the two panels is the same.
        if self.version is not None:
            self._fill_versions(data.get('version', ''))
        host_os = data.get('host_OS', '')
        self._set_combo_text(self.hostOS, HOST_OS.get(host_os, host_os))
        self.inactive.setChecked(data.get('inactive') in (True, 'True'))
        for attr, key in (
            ('last_modified', 'lastModified'),
            ('last_compiled', 'lastCompiled'),
            ('last_installed', 'lastInstalled'),
        ):
            ts = int(data.get(key, 0) or 0)
            text = (
                datetime.fromtimestamp(ts, tz=UTC).strftime('%Y-%m-%d %H:%M:%S')
                if ts
                else '-'
            )
            getattr(self, attr).setText(text)

        self.platform.currentTextChanged.connect(self._update_settings_buttons)
        if self.version is not None:
            # The two platforms gate different things on the release, so
            # the list belongs to the platform that is chosen.
            self.platform.currentTextChanged.connect(self._platform_changed)
        self.hostOS.currentTextChanged.connect(self._update_settings_buttons)
        self._update_settings_buttons()

    def validate(self):
        """``FirewallDialog::validate`` / ``ClusterDialog::validate``.

        The name, and no "/" in it (fwbuilder #2011): the name becomes the
        file the compiled script is written to.
        """
        refusal = super().validate()
        if refusal:
            return refusal
        if '/' in self.obj_name.text():
            return 'Character "/" is not allowed in firewall object name'
        return ''

    def _apply_changes(self):
        new_name = self.obj_name.text()
        if self._obj.name != new_name:
            self._obj.name = new_name
        old_data = self._obj.data or {}
        data = dict(old_data)
        data['platform'] = self.platform.currentText()
        if self.version is not None:
            # The item carries the stored value; the text is the label.
            data['version'] = self.version.currentData() or ''
        host_os_text = self.hostOS.currentText()
        data['host_OS'] = _HOST_OS_INTERNAL.get(host_os_text, host_os_text)
        _set_data_key(data, 'inactive', self.inactive.isChecked(), False)
        if data != old_data:
            self._obj.data = data

    def _update_settings_buttons(self):
        self.fwAdvanced.setEnabled(self.platform.currentText() in PLATFORMS.values())
        self.osAdvanced.setEnabled(self.hostOS.currentText() in HOST_OS.values())

    @Slot()
    def openFWDialog(self):
        dialog_cls = _PLATFORM_SETTINGS_DIALOG.get(self.platform.currentText())
        if dialog_cls is None:
            return
        dlg = dialog_cls(self._obj, parent=self.window())
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.changed.emit()

    @Slot()
    def openOSDialog(self):
        dlg = LinuxSettingsDialog(
            self._obj, platform=self.platform.currentText(), parent=self.window()
        )
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.changed.emit()

    def _platform_changed(self, _display=''):
        """Re-offer the releases of the platform that is now chosen.

        A release of the platform that was chosen before means nothing to
        the new one, so it is not carried over - `FirewallDialog::
        platformChanged` refills the list the same way and falls back to
        its first entry.
        """
        self._fill_versions(self.version.currentData() or '', keep_unlisted=False)

    def _fill_versions(self, stored, keep_unlisted=True):
        """Fill the release combo and select *stored*.

        Every item carries its stored value beside the label, because the
        two differ: Firewall Builder stores "1.2.5 or earlier" as
        ``lt_1.2.6``, and every entry is a range of releases stored as its
        first one.  The entries come newest first, and each label names
        the distributions it is right for.  A value the list does not offer - a data file
        written by another tool or by hand may name any release - is added
        as an item of its own, where Firewall Builder overwrites it with
        the first entry (`FirewallDialog::fillVersion`); showing the
        object the way it is beats editing it for looking at it.
        """
        platform = _PLATFORM_INTERNAL.get(self.platform.currentText(), '')
        self.version.clear()
        for value, label in get_versions_for_platform(platform):
            self.version.addItem(label, value)
        index = self.version.findData(stored)
        if index < 0 and stored and keep_unlisted:
            self.version.addItem(stored, stored)
            index = self.version.count() - 1
        elif not stored and keep_unlisted:
            # A firewall imported from a `.fwb`, or written before the list
            # had to be answered, names no release.  It is compiled for the
            # top entry, and the combo says that rather than pretending the
            # top entry was chosen - or letting a plain OK write it.
            self.version.insertItem(0, get_unset_version_label(platform), '')
            index = 0
        self.version.setCurrentIndex(max(index, 0))
        # The closed combo stays narrow (the .ui sets it to a minimum
        # content length), but the list opens wide enough for the
        # distributions each label names.
        # From the font rather than the view, which knows the width of its
        # items only once it has been shown.
        metrics = self.version.fontMetrics()
        widest = max(
            (
                metrics.horizontalAdvance(self.version.itemText(i))
                for i in range(self.version.count())
            ),
            default=0,
        )
        self.version.view().setMinimumWidth(widest + 40)

    @staticmethod
    def _set_combo_text(combo, text):
        idx = combo.findText(text)
        if idx >= 0:
            combo.setCurrentIndex(idx)
        elif text:
            combo.addItem(text)
            combo.setCurrentIndex(combo.count() - 1)


class ClusterDialog(FirewallDialog):
    """Editor panel for a Cluster.

    The firewall's panel without the iptables release.  Firewall Builder
    does not offer one on a cluster - `clusterdialog_q.ui` has no version
    combo and `newClusterDialog_create.cpp` writes only `platform` and
    `host_OS` - and neither compiler reads one: a member compiles for the
    release it names itself, so a combo here would show a setting that
    changes nothing.
    """

    #: No release combo in this panel, which is what the guards in
    #: `FirewallDialog` read.
    version = None

    def __init__(self, parent=None):
        BaseObjectDialog.__init__(self, 'clusterdialog_q.ui', parent)


class InterfaceDialog(BaseObjectDialog):
    def __init__(self, parent=None):
        super().__init__('interfacedialog_q.ui', parent)

    def _is_bridge_port(self):
        """Check if this interface is a bridge port."""
        return self._obj.is_bridge_port()

    def _run_autoconfigure(self):
        """Auto-detect interface type from name and parent context.

        Called both on load (``_populate``) and on save
        (``_apply_changes``); ``validate`` has refused a name that may
        not sit where the interface sits.
        """
        from firewallfabrik.gui.interface_autoconfigure import guess_interface_type

        parent = getattr(self._obj, 'parent_interface', None)
        guessed = guess_interface_type(self._obj.name or '', parent)

        if guessed:
            options = dict(self._obj.options or {})
            changed = False

            if guessed.pop('_set_unnumbered', False):
                old_data = self._obj.data or {}
                if not old_data.get('unnum', False):
                    new_data = dict(old_data)
                    new_data['unnum'] = True
                    self._obj.data = new_data

            for key, val in guessed.items():
                if key not in options or not options[key]:
                    options[key] = val
                    changed = True
            if changed:
                self._obj.options = options

    def _populate(self):
        # Autoconfigure interface type on load (like fwbuilder's loadFWObject).
        # Runs before populating the dialog so auto-detected values don't
        # trigger a false "changed" state.
        from PySide6.QtCore import QSettings

        if QSettings().value(
            'Objects/Interface/autoconfigureInterfaces', True, type=bool
        ):
            self._run_autoconfigure()

        self.obj_name.setText(self._obj.name or '')
        data = self._obj.data or {}
        self.label.setText(data.get('label', ''))
        self.seclevel.setValue(int(data.get('security_level', 0)))
        self.management.setChecked(bool(data.get('management', False)))
        self.dedicated_failover.setChecked(bool(data.get('dedicated_failover', False)))
        if data.get('dyn', False):
            self.dynamic.setChecked(True)
        elif data.get('unnum', False):
            self.unnumbered.setChecked(True)
        else:
            self.regular.setChecked(True)

        # Bridge port interfaces: hide regular options, show label.
        if self._is_bridge_port():
            self.regular.hide()
            self.dynamic.hide()
            self.unnumbered.hide()
            self.management.hide()
            self.dedicated_failover.hide()
            self.bridge_port_label.show()
        else:
            self.regular.show()
            self.dynamic.show()
            self.unnumbered.show()
            self.management.show()
            self.dedicated_failover.show()
            self.bridge_port_label.hide()

    def _apply_changes(self):
        new_name = self.obj_name.text()
        if self._obj.name != new_name:
            self._obj.name = new_name
        old_data = self._obj.data or {}
        data = dict(old_data)
        _set_data_key(data, 'label', self.label.text(), '')
        _set_data_key(data, 'security_level', str(self.seclevel.value()), '0')
        _set_data_key(data, 'management', self.management.isChecked(), False)
        _set_data_key(
            data, 'dedicated_failover', self.dedicated_failover.isChecked(), False
        )
        _set_data_key(data, 'dyn', self.dynamic.isChecked(), False)
        _set_data_key(data, 'unnum', self.unnumbered.isChecked(), False)
        if data != old_data:
            self._obj.data = data

        # Autoconfigure interface type from name if enabled in Preferences.
        if _autoconfigure_interfaces():
            self._run_autoconfigure()

    def validate(self):
        """``InterfaceDialog::validate`` (InterfaceDialog.cpp:317).

        The name, then ``basicValidateInterfaceName`` - no white space on
        Linux - and, with "autoconfigure interfaces" on, whether an
        interface of this name may sit where this one sits
        (``interfaceProperties::validateInterface``): a VLAN name has to
        name its parent, and only a bridge or a bond takes a sub-interface
        that is not a VLAN.
        """
        refusal = super().validate()
        if refusal:
            return refusal
        from firewallfabrik.driver._interface_properties import (
            LinuxInterfaceProperties,
        )

        props = LinuxInterfaceProperties()
        name = self.obj_name.text()
        refusal = props.basic_name_problem(name)
        if refusal or not _autoconfigure_interfaces():
            return refusal
        parent = self._obj.parent_interface or self._obj.device
        if parent is None:
            return ''
        return props.interface_problem(parent, self._obj, name=name)

    @Slot()
    def openIfaceDialog(self):
        """Open the advanced interface settings dialog (device type, VLAN, bridge, bonding)."""
        from firewallfabrik.gui.iface_opts_dialog import IfaceOptsDialog

        dlg = IfaceOptsDialog(self._obj, parent=self.window())
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.changed.emit()
