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

"""File > Import Firewall, clicked through from the files to the firewall."""

import pytest

pytest.importorskip('PySide6')

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from firewallfabrik.gui.import_firewall_wizard import ImportFirewallWizard
from tests.test_importer import IMPORT_DIR, _new_database


@pytest.fixture(scope='module')
def _application():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def wizard(_application):
    db_manager, library_id = _new_database()
    dialog = ImportFirewallWizard(db_manager, library_id)
    dialog.show()
    yield dialog
    dialog.close()


def test_the_wizard_imports_both_formats_into_one_firewall(wizard):
    source = wizard.currentPage()
    source.fileName.setText(
        f'{IMPORT_DIR / "sample-iptables-save.txt"};{IMPORT_DIR / "sample-nft.json"}'
    )
    assert source.isComplete()
    wizard.next()
    content = wizard.currentPage()
    texts = [content.tables.item(i).text() for i in range(content.tables.count())]
    assert any('table inet t' in text for text in texts)
    # nftables is the default platform, whatever the input was.
    assert content.platform.currentData() == 'nftables'
    # Only the nftables tables.
    for i in range(content.tables.count()):
        item = content.tables.item(i)
        if 'iptables-save' in item.text():
            item.setCheckState(Qt.CheckState.Unchecked)
    wizard.next()
    name = wizard.currentPage()
    name.firewallName.setText('imported-fw')
    wizard.next()
    progress = wizard.currentPage()
    assert wizard.fw_id is not None
    assert progress.errors_count_display.text() == '0'
    assert 'Firewall "imported-fw" created' in progress.importLog.toPlainText()


def test_the_name_of_an_existing_firewall_is_refused(wizard, monkeypatch):
    from PySide6.QtWidgets import QMessageBox

    monkeypatch.setattr(QMessageBox, 'warning', lambda *args: None)
    wizard.currentPage().fileName.setText(str(IMPORT_DIR / 'sample-nft.json'))
    wizard.next()
    wizard.next()
    name = wizard.currentPage()
    name.firewallName.setText('dup')
    wizard.next()
    assert wizard.fw_id is not None
    wizard.fw_id = None
    wizard.restart()
    wizard.currentPage().fileName.setText(str(IMPORT_DIR / 'sample-nft.json'))
    wizard.next()
    wizard.next()
    wizard.currentPage().firewallName.setText('dup')
    assert wizard.currentPage().validatePage() is False


def test_the_routes_read_over_ssh_become_the_routing_rule_set(wizard, monkeypatch):
    from firewallfabrik.core.objects import Firewall
    from firewallfabrik.gui import ruleset_lookup

    def run(*_args, **_kwargs):
        return ruleset_lookup.RemoteRuleset(
            nft_json=(IMPORT_DIR / 'sample-nft.json').read_text(),
            ip_addr_json=(IMPORT_DIR / 'sample-routes-addr.json').read_text(),
            ip_route4_json=(IMPORT_DIR / 'sample-routes4.json').read_text(),
            ip_route6_json=(IMPORT_DIR / 'sample-routes6.json').read_text(),
            hostname='gw.example.com',
        )

    monkeypatch.setattr(ruleset_lookup, 'run', run)
    source = wizard.currentPage()
    source.fromFirewall.setChecked(True)
    source.address.setText('192.0.2.1')
    wizard.next()
    content = wizard.currentPage()
    routes = next(
        content.tables.item(i)
        for i in range(content.tables.count())
        if content.tables.item(i).text().startswith('ip route')
    )
    # The listing has a DHCP route and a blackhole, which the script would
    # delete: the routes wait for a deliberate check.
    assert routes.checkState() == Qt.CheckState.Unchecked
    assert 'deletes those' in content.summary.text()
    routes.setCheckState(Qt.CheckState.Checked)
    wizard.next()
    assert wizard.currentPage().firewallName.text() == 'gw'
    wizard.next()
    assert wizard.fw_id is not None
    with wizard.db_manager.session() as session:
        fw = session.get(Firewall, wizard.fw_id)
        routing = next(rs for rs in fw.rule_sets if type(rs).__name__ == 'Routing')
        # Six IPv4 routes, the multi path one as two rules, and two IPv6
        # routes.
        assert len(routing.rules) == 9
