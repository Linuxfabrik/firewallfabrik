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

"""Editor lifecycle management extracted from FWWindow.

Handles opening, saving, closing, and switching object editors in the
bottom editor dock panel.
"""

import logging
import uuid
from collections import namedtuple
from datetime import UTC, datetime

import sqlalchemy
import sqlalchemy.exc
from PySide6.QtCore import QObject, Signal, Slot
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QMessageBox
from sqlalchemy import inspect as sa_inspect

from firewallfabrik.core.objects import (
    Address,
    Firewall,
    Group,
    Host,
    Interface,
    Interval,
    Library,
    Rule,
    RuleSet,
    Service,
    group_membership,
    rule_elements,
)
from firewallfabrik.gui.policy_model import _action_label

logger = logging.getLogger(__name__)


def _find_parent_firewall(obj):
    """Walk up the object hierarchy to find the owning Firewall/Cluster.

    Returns the Firewall/Cluster instance, or *None* if *obj* is not
    under a device (e.g. a standalone library object).  Mirrors
    fwbuilder's ``UsageResolver::findFirewallsForObject`` direct-parent
    walk (``while (f && !Firewall::cast(f)) f=f->getParent()``).
    """
    if isinstance(obj, Firewall):
        return obj
    if isinstance(obj, Interface):
        # Sub-interface → walk up to top-level interface first.
        iface = obj
        while iface.parent_interface is not None:
            iface = iface.parent_interface
        device = iface.device
        return device if isinstance(device, Firewall) else None
    if isinstance(obj, Address) and obj.interface is not None:
        return _find_parent_firewall(obj.interface)
    return None


def _session_has_real_changes(session):
    """Return *True* only if the session contains actual value changes.

    ``apply_all()`` unconditionally re-assigns widget values to ORM
    attributes, which makes SQLAlchemy mark JSON/dict columns as dirty
    even when the content is identical.  This helper compares current
    attribute values against their committed (pre-edit) state so we
    can skip the commit when nothing really changed.
    """
    if session.new or session.deleted:
        return True
    for obj in session.dirty:
        committed = sa_inspect(obj).committed_state
        for key, old_val in committed.items():
            if getattr(obj, key, old_val) != old_val:
                return True
    return False


def _find_referencing_firewalls(session, obj_id):
    """Find all Firewalls whose rules reference *obj_id*.

    Walks up the group hierarchy (transitively) so that editing a
    member of a ServiceGroup also stamps Firewalls using that group.
    Mirrors fwbuilder's ``UsageResolver::findFirewallsForObject``
    rule-element search.
    """
    # Collect the object itself plus all groups (transitively) containing it.
    search_ids = {obj_id}
    queue = [obj_id]
    while queue:
        member_id = queue.pop()
        parent_group_ids = set(
            session.scalars(
                sqlalchemy.select(group_membership.c.group_id).where(
                    group_membership.c.member_id == member_id,
                ),
            ).all()
        )
        for gid in parent_group_ids:
            if gid not in search_ids:
                search_ids.add(gid)
                queue.append(gid)

    # Find every Firewall that references any of these IDs in its rules.
    device_ids = set(
        session.scalars(
            sqlalchemy.select(RuleSet.device_id)
            .distinct()
            .join(Rule, Rule.rule_set_id == RuleSet.id)
            .join(rule_elements, rule_elements.c.rule_id == Rule.id)
            .where(rule_elements.c.target_id.in_(search_ids)),
        ).all()
    )

    firewalls = []
    for did in device_ids:
        fw = session.get(Host, did)
        if isinstance(fw, Firewall):
            firewalls.append(fw)
    return firewalls


# Messages shown when double-clicking an "Any" element in a rule cell.
# Keyed by slot name so they work for Policy, NAT and Routing rule sets.
_ANY_MSG_ADDRESS = (
    'When used in the Source or Destination field of a rule, '
    'the Any object will match all IP addresses. '
    'To update your rule to match only specific IP addresses, '
    'drag-and-drop an object from the Object tree into the field '
    'in the rule.'
)
_ANY_MSG_INTERFACE = (
    'When used in an Interface field of a rule, '
    'the Any object will match all interfaces. '
    'To update your rule to match only a specific interface, '
    'drag-and-drop an object from the Object tree into the field '
    'in the rule.'
)
_ANY_MSG_SERVICE = (
    'When used in the Service field of a rule, '
    'the Any object will match all IP, ICMP, TCP or UDP services. '
    'To update your rule to match only specific service, '
    'drag-and-drop an object from the Object tree into the field '
    'in the rule.'
)
_ANY_MSG_TIME = (
    'When used in the Time Interval field of a rule, '
    'the Any object will match any time of the day or day '
    'of the week. To update your rule to match only specific '
    'service, drag-and-drop an object from the Object tree into '
    'the field in the rule.'
)
_ANY_MESSAGES = {
    # Policy
    'dst': _ANY_MSG_ADDRESS,
    'itf': _ANY_MSG_INTERFACE,
    'src': _ANY_MSG_ADDRESS,
    'srv': _ANY_MSG_SERVICE,
    'when': _ANY_MSG_TIME,
    # NAT
    'itf_inb': _ANY_MSG_INTERFACE,
    'itf_outb': _ANY_MSG_INTERFACE,
    'odst': _ANY_MSG_ADDRESS,
    'osrc': _ANY_MSG_ADDRESS,
    'osrv': _ANY_MSG_SERVICE,
    'tdst': _ANY_MSG_ADDRESS,
    'tsrc': _ANY_MSG_ADDRESS,
    'tsrv': _ANY_MSG_SERVICE,
    # Routing
    'rdst': _ANY_MSG_ADDRESS,
    'rgtw': _ANY_MSG_ADDRESS,
    'ritf': _ANY_MSG_INTERFACE,
}
_ANY_ICON_TYPE = {
    'dst': 'Network',
    'itf': 'Interface',
    'itf_inb': 'Interface',
    'itf_outb': 'Interface',
    'odst': 'Network',
    'osrc': 'Network',
    'osrv': 'IPService',
    'rdst': 'Network',
    'rgtw': 'Network',
    'ritf': 'Interface',
    'src': 'Network',
    'srv': 'IPService',
    'tdst': 'Network',
    'tsrc': 'Network',
    'tsrv': 'IPService',
    'when': 'Interval',
}

# Map object type discriminator strings to their SQLAlchemy model class.
_MODEL_MAP = {
    'AddressRange': Address,
    'AddressTable': Group,
    'Cluster': Host,
    'CustomService': Service,
    'DNSName': Group,
    'DynamicGroup': Group,
    'Firewall': Host,
    'Host': Host,
    'ICMP6Service': Service,
    'ICMPService': Service,
    'IPService': Service,
    'IPv4': Address,
    'IPv6': Address,
    'Interface': Interface,
    'Interval': Interval,
    'IntervalGroup': Group,
    'Library': Library,
    'NAT': RuleSet,
    'Network': Address,
    'NetworkIPv6': Address,
    'ObjectGroup': Group,
    'PhysAddress': Address,
    'Policy': RuleSet,
    'Routing': RuleSet,
    'ServiceGroup': Group,
    'TCPService': Service,
    'TagService': Service,
    'UDPService': Service,
    'UserService': Service,
}


def _device_prefix(obj):
    """Return ``'device_name: '`` if *obj* is a child of a device, else ``''``.

    Walks up the ORM parent chain looking for a :class:`Host` (the base
    class for Firewall / Cluster / Host).
    """
    current = obj
    while current is not None:
        if isinstance(current, Host):
            return f'{current.name}: '
        if isinstance(current, Address):
            current = current.interface or current.group or current.library
        elif isinstance(current, Interface):
            current = current.device or current.library
        elif isinstance(current, RuleSet):
            current = current.device
        elif isinstance(current, Rule):
            rs = current.rule_set
            current = rs.device if rs else None
        else:
            break
    return ''


def _undo_desc(action, obj_type, name, old_name=None, prefix=''):
    """Build a short undo description.

    Supported *action* values: ``Delete``, ``Edit``, ``New``, ``Rename``.
    For ``Rename``, *old_name* must be provided.
    *prefix* is prepended as-is (e.g. ``"fw-test: "``).
    """
    if action == 'Rename':
        return f'{prefix}Rename {obj_type} {old_name} > {name}'
    return f'{prefix}{action} {obj_type} {name}'


def _build_editor_path(obj):
    """Build a ``" / "``-separated path from *obj* up to its Library.

    Mirrors fwbuilder's ``buildEditorTitleAndIcon()`` — walk up the ORM
    parent chain, collect names, and join them root-first.
    """
    parts = []
    current = obj
    while current is not None:
        parts.append(current.name)
        if isinstance(current, Library):
            break
        # Determine the parent depending on object type.
        if isinstance(current, Address):
            current = current.interface or current.group or current.library
        elif isinstance(current, Interface):
            current = current.device or current.library
        elif isinstance(current, RuleSet):
            current = current.device
        elif isinstance(current, (Host, Service, Interval)):
            current = current.group or current.library
        elif isinstance(current, Group):
            current = current.parent_group or current.library
        else:
            break
    parts.reverse()
    return ' / '.join(parts)


# Lightweight struct carrying the UI widget references EditorManager needs.
EditorManagerUI = namedtuple(
    'EditorManagerUI',
    [
        'actions_dialog',
        'blank_dialog',
        'comment_panel',
        'dock',
        'editor_action',
        'get_display_file',
        'icon',
        'metric_editor',
        'nat_rule_options',
        'routing_rule_options',
        'rule_options',
        'stack',
        'tab_widget',
    ],
)


class EditorManager(QObject):
    """Manages object editor lifecycle: open, save, close, switch."""

    # Signals for side effects FWWindow handles.
    object_saved = Signal(object)  # ORM obj after commit -> tree update
    mdi_titles_changed = Signal(object)  # Firewall obj -> MDI title sync
    editor_opened = Signal(object, str)  # (obj, obj_type) -> parent ruleset

    def __init__(self, db_manager, editor_map, ui, blank_label, parent=None):
        """Initialise the editor manager.

        Args:
            db_manager: DatabaseManager instance.
            editor_map: dict[str, BaseObjectDialog] — widget per obj type.
            ui: EditorManagerUI namedtuple with widget references.
            blank_label: QLabel used for "Any" / direction messages.
            parent: QObject parent (typically FWWindow).
        """
        super().__init__(parent)
        self._db_manager = db_manager
        self._editor_map = editor_map
        self._ui = ui
        self._blank_label = blank_label

        self._current_editor = None
        self._editor_session = None
        self._editor_obj_id = None
        self._editor_obj_name = None
        self._editor_obj_type = None

    # --- Properties (read by FWWindow._on_create_group_member etc.) ---

    @property
    def current_editor(self):
        return self._current_editor

    @property
    def current_session(self):
        return self._editor_session

    @property
    def current_obj_id(self):
        return self._editor_obj_id

    @property
    def current_obj_type(self):
        return self._editor_obj_type

    # --- Lifecycle ---

    def set_db_manager(self, db_manager):
        """Replace the database manager (called on file new/open/close)."""
        self._db_manager = db_manager
        self._propagate_db_manager()

    def _propagate_db_manager(self):
        """Forward the current db_manager to dialogs that need it."""
        from firewallfabrik.gui.dynamic_group_dialog import DynamicGroupDialog

        for widget in set(self._editor_map.values()):
            if isinstance(widget, DynamicGroupDialog):
                widget.set_db_manager(self._db_manager)

    def connect_dialogs(self):
        """Wire changed signals on all editor dialog widgets."""
        from firewallfabrik.gui.base_object_dialog import BaseObjectDialog

        for widget in set(self._editor_map.values()):
            if isinstance(widget, BaseObjectDialog):
                widget.changed.connect(self.on_editor_changed)

        self._propagate_db_manager()

    # --- Public methods ---

    def open_object(self, obj_id, obj_type):
        """Open the editor panel for the given object."""
        dialog_widget = self._editor_map.get(obj_type)
        if dialog_widget is None:
            return

        model_cls = _MODEL_MAP.get(obj_type)
        if model_cls is None:
            return

        # Flush pending changes from the current editor before switching.
        self.flush()

        # Close any previous editor session to avoid leaks.
        if self._editor_session is not None:
            self._editor_session.close()

        self._editor_session = self._db_manager.create_session()
        obj = self._editor_session.get(model_cls, uuid.UUID(obj_id))
        if obj is None:
            self._editor_session.close()
            self._editor_session = None
            return

        all_tags = self.gather_all_tags(self._editor_session)
        dialog_widget.load_object(obj, all_tags=all_tags)
        self._current_editor = dialog_widget
        self._editor_obj_id = obj_id
        self._editor_obj_name = obj.name
        self._editor_obj_type = obj_type

        # The dialog widget sits inside a page's layout, not as a direct
        # page of the stacked widget — switch to its parent page instead.
        self._ui.stack.setCurrentWidget(dialog_widget.parentWidget())
        self.show_editor_panel()

        path = _build_editor_path(obj)
        display = self._ui.get_display_file()
        if display:
            path = f'[{display}] / {path}'
        self._ui.dock.setWindowTitle(path)

        icon_path = f':/Icons/{obj_type}/icon-big'
        pixmap = QIcon(icon_path).pixmap(64, 64)
        if not pixmap.isNull():
            self._ui.icon.setPixmap(pixmap)

        if not self._ui.dock.isVisible():
            self._ui.dock.setVisible(True)
            self._ui.editor_action.setChecked(True)

        # Focus the first editable widget in the editor panel.
        dialog_widget.setFocus()
        dialog_widget.focusNextChild()

        # Signal FWWindow to open the parent device's policy if needed.
        self.editor_opened.emit(obj, obj_type)

    @Slot()
    def on_editor_changed(self):
        """Handle a change in the active editor: apply and commit."""
        editor = self._current_editor
        session = self._editor_session
        if editor is None or session is None:
            return
        editor.apply_all()
        # Capture path while the session is still usable (before a
        # potential rollback which would expire all ORM state).
        obj = getattr(editor, '_obj', None)
        obj_path = _build_editor_path(obj) if obj else None

        # Only persist when attribute values actually differ from their
        # committed state.  apply_all() unconditionally re-assigns
        # widget values, which marks JSON columns as dirty even when
        # the content is identical (see _session_has_real_changes).
        has_changes = _session_has_real_changes(session)
        fw = _find_parent_firewall(obj) if obj is not None else None
        ref_firewalls = []

        if has_changes:
            # Stamp the lastModified timestamp on the owning
            # Firewall/Cluster so the compile dialog and bold-tree
            # display know recompilation is needed.  Walk up the
            # hierarchy (Address → Interface → Firewall) just like
            # fwbuilder's UsageResolver::findFirewallsForObject.
            now_epoch = None
            if fw is not None:
                now_epoch = int(datetime.now(tz=UTC).timestamp())
                data = dict(fw.data or {})
                data['lastModified'] = now_epoch
                fw.data = data
            elif obj is not None:
                # Shared library object: stamp every Firewall that
                # references it (directly or through group membership).
                ref_firewalls = _find_referencing_firewalls(
                    session,
                    obj.id,
                )
                if ref_firewalls:
                    now_epoch = int(datetime.now(tz=UTC).timestamp())
                    for rfw in ref_firewalls:
                        data = dict(rfw.data or {})
                        data['lastModified'] = now_epoch
                        rfw.data = data

            try:
                session.commit()
            except sqlalchemy.exc.IntegrityError as e:
                session.rollback()
                if 'UNIQUE constraint failed' in str(e):
                    if obj_path:
                        detail = obj_path.replace(' / ', ' > ')
                        msg = f'Duplicate names are not allowed: {detail}'
                    else:
                        msg = 'Duplicate names are not allowed.'
                    QMessageBox.critical(self.parent(), 'FirewallFabrik', msg)
                else:
                    logger.exception('Commit failed')
                return

            # Build a human-readable undo description.
            obj = getattr(editor, '_obj', None)
            if obj is not None:
                prefix = _device_prefix(obj)
                obj_type = getattr(obj, 'type', type(obj).__name__)
                old_name = self._editor_obj_name or ''
                new_name = obj.name
                if old_name and new_name != old_name:
                    desc = _undo_desc(
                        'Rename',
                        obj_type,
                        new_name,
                        old_name=old_name,
                        prefix=prefix,
                    )
                else:
                    desc = _undo_desc('Edit', obj_type, new_name, prefix=prefix)
                self._editor_obj_name = new_name
            else:
                desc = 'Editor change'
            self._db_manager.save_state(desc)

            # Update the editor panel's "Modified" label for firewalls.
            if now_epoch is not None:
                label = getattr(editor, 'last_modified', None)
                if label is not None:
                    label.setText(
                        datetime.fromtimestamp(now_epoch, tz=UTC).strftime(
                            '%Y-%m-%d %H:%M:%S'
                        )
                    )

        # Always keep the tree in sync with the editor — even when
        # SQLAlchemy does not flag the session as dirty (JSON column
        # change detection can miss dict value changes).
        if obj is not None:
            self.object_saved.emit(obj)

        # Also refresh the parent Firewall tree item so its bold state
        # (needs-compile) is updated when a child object was edited.
        if fw is not None:
            if fw is not obj:
                self.object_saved.emit(fw)
            self.mdi_titles_changed.emit(fw)

        # Refresh all referencing Firewalls for shared library objects.
        for rfw in ref_firewalls:
            self.object_saved.emit(rfw)
            self.mdi_titles_changed.emit(rfw)

    def close(self):
        """Close the current editor session."""
        self.flush()
        if self._editor_session is not None:
            self._editor_session.close()
        self._editor_session = None
        self._current_editor = None
        self._editor_obj_id = None
        self._editor_obj_type = None
        self._ui.dock.setWindowTitle('Editor')

    def flush(self):
        """Apply any pending editor widget changes to the database.

        QLineEdit only fires ``editingFinished`` on focus loss or Enter.
        When the user presses Ctrl+S (or switches objects, closes files,
        etc.) while a QLineEdit still has focus, the signal hasn't fired
        yet.  Calling this method ensures the current widget values are
        written to the ORM object and committed before any save/close
        operation.
        """
        if self._current_editor is not None and self._editor_session is not None:
            self.on_editor_changed()

    def open_comment_editor(self, model, index):
        """Open the comment editor panel in the editor pane."""
        self.close()

        self._ui.comment_panel.load_rule(model, index)
        self._ui.stack.setCurrentWidget(
            self._ui.comment_panel.parentWidget(),
        )
        self.show_editor_panel()
        self._ui.dock.setWindowTitle('Comment')

        pixmap = QIcon(':/Icons/Comment/icon-big').pixmap(64, 64)
        if pixmap.isNull():
            pixmap = QIcon(':/Icons/Policy/icon-big').pixmap(64, 64)
        if not pixmap.isNull():
            self._ui.icon.setPixmap(pixmap)

    def open_rule_options(self, model, index):
        """Open the rule options panel in the editor pane."""
        self.close()

        if model.rule_set_type == 'NAT':
            panel = self._ui.nat_rule_options
        elif model.rule_set_type == 'Routing':
            panel = self._ui.routing_rule_options
        else:
            panel = self._ui.rule_options
        panel.load_rule(model, index)
        self._ui.stack.setCurrentWidget(panel.parentWidget())
        self.show_editor_panel()
        self._ui.dock.setWindowTitle('Rule Options')

        pixmap = QIcon(':/Icons/Options/icon-big').pixmap(64, 64)
        if not pixmap.isNull():
            self._ui.icon.setPixmap(pixmap)

    def open_metric_editor(self, model, index):
        """Open the metric editor panel in the editor pane."""
        self.close()

        self._ui.metric_editor.load_rule(model, index)
        self._ui.stack.setCurrentWidget(
            self._ui.metric_editor.parentWidget(),
        )
        self.show_editor_panel()
        self._ui.dock.setWindowTitle('Metric')

        pixmap = QIcon(':/Icons/Routing/icon-big').pixmap(64, 64)
        if not pixmap.isNull():
            self._ui.icon.setPixmap(pixmap)

    def open_action_editor(self, model, index):
        """Open the action parameters panel in the editor pane."""
        self.close()

        self._ui.actions_dialog.load_rule(model, index)
        self._ui.stack.setCurrentWidget(
            self._ui.actions_dialog.parentWidget(),
        )
        self.show_editor_panel()

        # Determine the action name for title and icon.
        row_data = model.get_row_data(index)
        action_enum = 'Policy'
        if row_data is not None:
            action_enum = row_data.action or 'Policy'
        self._ui.dock.setWindowTitle(
            f'Action: {_action_label(action_enum)}',
        )

        icon_path = f':/Icons/{action_enum}/icon-big'
        pixmap = QIcon(icon_path).pixmap(64, 64)
        if pixmap.isNull():
            pixmap = QIcon(':/Icons/Policy/icon-big').pixmap(64, 64)
        if not pixmap.isNull():
            self._ui.icon.setPixmap(pixmap)

    def open_direction_editor(self, model, index):
        """Open the (blank) direction pane in the editor pane."""
        self.close()

        self._blank_label.clear()
        self._ui.stack.setCurrentWidget(
            self._ui.blank_dialog.parentWidget(),
        )
        self.show_editor_panel()

        row_data = model.get_row_data(index)
        direction_name = 'Both'
        if row_data is not None:
            direction_name = row_data.direction or 'Both'
        self._ui.dock.setWindowTitle(f'Direction: {direction_name}')

        icon_path = f':/Icons/{direction_name}/icon-big'
        pixmap = QIcon(icon_path).pixmap(64, 64)
        if pixmap.isNull():
            pixmap = QIcon(':/Icons/Policy/icon-big').pixmap(64, 64)
        if not pixmap.isNull():
            self._ui.icon.setPixmap(pixmap)

    def show_any_editor(self, slot):
        """Show the 'Any' object description in the editor pane."""
        self.close()

        msg = _ANY_MESSAGES.get(slot, '')
        self._blank_label.setText(msg)
        self._ui.stack.setCurrentWidget(
            self._ui.blank_dialog.parentWidget(),
        )
        self.show_editor_panel()
        self._ui.dock.setWindowTitle('Any')

        icon_type = _ANY_ICON_TYPE.get(slot, 'Policy')
        pixmap = QIcon(f':/Icons/{icon_type}/icon-big').pixmap(64, 64)
        if not pixmap.isNull():
            self._ui.icon.setPixmap(pixmap)

    def show_editor_panel(self):
        """Show the editor dock and switch to the Editor tab."""
        if not self._ui.dock.isVisible():
            self._ui.dock.setVisible(True)
            self._ui.editor_action.setChecked(True)
        self._ui.tab_widget.setCurrentIndex(0)

    @staticmethod
    def gather_all_tags(session):
        """Collect every tag used across all object tables."""
        all_tags = set()
        for cls in (Address, Group, Host, Interface, Interval, Service):
            for (tag_set,) in session.execute(sqlalchemy.select(cls.keywords)):
                if tag_set:
                    all_tags.update(tag_set)
        return all_tags
