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

"""An object's tags survive an import, and a Dynamic Group selects on them.

Firewall Builder writes the tags of every object as one comma-separated
`keywords` attribute (`FWObject::toXML`, `setToString`) and reads them
back with `stringToSet`.  The `.fwb` reader left them in the untyped
`data` dict, where the editor's tag field and `_matches_dynamic_criteria`
- the only two consumers - never look, so an imported object came in
untagged and every Dynamic Group naming a tag resolved to nothing.
"""

import textwrap

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.compiler._compiler import _matches_dynamic_criteria
from firewallfabrik.core.objects import Host, Interface, IPv4, ObjectGroup

FWB = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE FWObjectDatabase>
<FWObjectDatabase xmlns="http://www.fwbuilder.org/1.0/" version="24">
  <Library id="sysid0" name="User" comment="" color="#d2ffd2" ro="False">
    <ObjectGroup id="g1" name="Objects" comment="" ro="False">
      <ObjectGroup id="g2" name="Hosts" comment="" ro="False" keywords="prod,dmz">
        <Host id="h1" name="tagged-host" comment="" ro="False" keywords="prod">
          <Interface id="i1" name="eth0" comment="" ro="False" dyn="False"
                     unnum="False" unprotected="False" security_level="0"
                     label="" dedicated_failover="False" keywords="edge">
            <IPv4 id="a1" name="tagged-host:eth0:ip" comment="" ro="False"
                  address="10.0.0.5" netmask="255.255.255.0" keywords="edge,ip"/>
          </Interface>
        </Host>
        <Host id="h2" name="plain-host" comment="" ro="False">
          <Interface id="i2" name="eth0" comment="" ro="False" dyn="False"
                     unnum="False" unprotected="False" security_level="0"
                     label="" dedicated_failover="False">
            <IPv4 id="a2" name="plain-host:eth0:ip" comment="" ro="False"
                  address="10.0.0.6" netmask="255.255.255.0"/>
          </Interface>
        </Host>
      </ObjectGroup>
    </ObjectGroup>
  </Library>
</FWObjectDatabase>
"""


@pytest.fixture(scope='module')
def session(tmp_path_factory):
    path = tmp_path_factory.mktemp('keywords') / 'tags.fwb'
    path.write_text(textwrap.dedent(FWB))
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(path))
    with db.session() as session:
        yield session


def _one(session, cls, name):
    return (
        session.execute(
            sqlalchemy.select(cls).where(cls.name == name),
        )
        .scalars()
        .first()
    )


@pytest.mark.parametrize(
    ('cls', 'name', 'expected'),
    [
        (ObjectGroup, 'Hosts', {'prod', 'dmz'}),
        (Host, 'tagged-host', {'prod'}),
        (Interface, 'eth0', {'edge'}),
        (IPv4, 'tagged-host:eth0:ip', {'edge', 'ip'}),
    ],
)
def test_the_tags_come_across(session, cls, name, expected):
    assert _one(session, cls, name).keywords == expected


def test_an_untagged_object_stays_untagged(session):
    assert not _one(session, Host, 'plain-host').keywords


def test_the_tag_is_not_left_in_the_untyped_data_dict(session):
    """`data` is what the readers put an attribute they do not know into."""
    assert 'keywords' not in (_one(session, Host, 'tagged-host').data or {})


def test_a_dynamic_group_selects_on_the_imported_tag(session):
    """The one consumer in the compiler, and the reason this matters."""
    criteria = [{'type': 'Host', 'keyword': 'prod'}]
    assert _matches_dynamic_criteria(_one(session, Host, 'tagged-host'), criteria)
    assert not _matches_dynamic_criteria(_one(session, Host, 'plain-host'), criteria)
