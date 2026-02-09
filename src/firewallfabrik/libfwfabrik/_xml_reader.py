"""XML reader for Firewall Builder (.fwb) files.

Parses the fwbuilder XML format into the multi-table SQLAlchemy model.
All XML string IDs are mapped to UUIDs.  Cross-element references
(ObjectRef, ServiceRef, IntervalRef) are resolved after the full tree
is parsed.
"""

import dataclasses
import logging
import uuid
import xml.etree.ElementTree

from . import models

logger = logging.getLogger(__name__)

NS = '{http://www.fwbuilder.org/1.0/}'

_ADDRESS_TAGS = {
    'IPv4': models.IPv4,
    'IPv6': models.IPv6,
    'Network': models.Network,
    'NetworkIPv6': models.NetworkIPv6,
    'PhysAddress': models.PhysAddress,
    'AddressRange': models.AddressRange,
    'MultiAddressRunTime': models.MultiAddressRunTime,
    'AnyNetwork': models.Network,
    'DummyNetwork': models.Network,
}

_SERVICE_TAGS = {
    'TCPService': models.TCPService,
    'UDPService': models.UDPService,
    'ICMPService': models.ICMPService,
    'ICMP6Service': models.ICMP6Service,
    'IPService': models.IPService,
    'CustomService': models.CustomService,
    'UserService': models.UserService,
    'TagService': models.TagService,
    'AnyIPService': models.IPService,
    'DummyIPService': models.IPService,
}

_DEVICE_TAGS = {
    'Host': models.Host,
    'Firewall': models.Firewall,
    'Cluster': models.Cluster,
}

_GROUP_TAGS = {
    'ObjectGroup': models.ObjectGroup,
    'ServiceGroup': models.ServiceGroup,
    'IntervalGroup': models.IntervalGroup,
    'ClusterGroup': models.ClusterGroup,
    'FailoverClusterGroup': models.FailoverClusterGroup,
    'StateSyncClusterGroup': models.StateSyncClusterGroup,
    'DNSName': models.DNSName,
    'AddressTable': models.AddressTable,
    'AttachedNetworks': models.AttachedNetworks,
    'DynamicGroup': models.DynamicGroup,
    'MultiAddress': models.MultiAddress,
}

_RULESET_TAGS = {
    'Policy': models.Policy,
    'NAT': models.NAT,
    'Routing': models.Routing,
}

_RULE_TAGS = {
    'PolicyRule': models.PolicyRule,
    'NATRule': models.NATRule,
    'RoutingRule': models.RoutingRule,
}

# Rule element container tag -> slot name
_SLOT_NAMES = {
    'Src': 'src',
    'Dst': 'dst',
    'Srv': 'srv',
    'Itf': 'itf',
    'When': 'when',
    'OSrc': 'osrc',
    'ODst': 'odst',
    'OSrv': 'osrv',
    'TSrc': 'tsrc',
    'TDst': 'tdst',
    'TSrv': 'tsrv',
    'ItfInb': 'itf_inb',
    'ItfOutb': 'itf_outb',
    'RDst': 'rdst',
    'RGtw': 'rgtw',
    'RItf': 'ritf',
}

_REF_TAGS = frozenset({'ObjectRef', 'ServiceRef', 'IntervalRef'})

_OPTIONS_TAGS = frozenset({
    'FirewallOptions',
    'HostOptions',
    'ClusterGroupOptions',
    'InterfaceOptions',
    'PolicyRuleOptions',
    'NATRuleOptions',
    'RoutingRuleOptions',
    'RuleSetOptions',
})

_POLICY_ACTIONS = {
    'Unknown': 0,
    'Accept': 1,
    'Reject': 2,
    'Deny': 3,
    'Scrub': 4,
    'Return': 5,
    'Skip': 6,
    'Continue': 7,
    'Accounting': 8,
    'Modify': 9,
    'Pipe': 10,
    'Custom': 11,
    'Branch': 12,
}

_DIRECTIONS = {
    'Undefined': 0,
    'Inbound': 1,
    'Outbound': 2,
    'Both': 3,
}

_NAT_ACTIONS = {
    'Translate': 0,
    'Branch': 1,
}

# Attributes handled explicitly -- everything else goes into ``data``.
_COMMON_KNOWN = frozenset({'id', 'name', 'comment', 'ro'})


@dataclasses.dataclass
class ParseResult:
    """Holds the parsed object graph and deferred association-table rows."""
    database: models.FWObjectDatabase
    memberships: list[dict]
    rule_element_rows: list[dict]


def _tag(elem):
    """Strip the fwbuilder namespace prefix from an element tag."""
    return elem.tag.removeprefix(NS)


def _bool(value):
    """Parse an XML boolean string to Python bool."""
    return value.lower() in ('true', '1', 'yes')


def _int(value, default=0):
    """Parse an XML integer string, returning *default* on failure."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def _extra_attrs(elem, known):
    """Return a dict of XML attributes not in *known*."""
    return {k: v for k, v in elem.attrib.items() if k not in known}


def _parse_options_children(elem):
    """Parse ``<Option name="k">v</Option>`` children into a dict."""
    result = {}
    for child in elem:
        if _tag(child) == 'Option':
            name = child.get('name', '')
            if name:
                result[name] = child.text or ''
    return result


def _parse_management_elem(elem):
    """Parse a ``<Management>`` element into a JSON-ready dict."""
    mgmt = {'address': elem.get('address', '')}
    for child in elem:
        tag = _tag(child)
        if tag == 'SNMPManagement':
            mgmt['snmp'] = {
                'enabled': _bool(child.get('enabled', 'False')),
                'read_community': child.get('snmp_read_community', ''),
                'write_community': child.get('snmp_write_community', ''),
            }
        elif tag == 'FWBDManagement':
            mgmt['fwbd'] = {
                'enabled': _bool(child.get('enabled', 'False')),
                'identity': child.get('identity', ''),
                'port': _int(child.get('port', '-1')),
            }
        elif tag == 'PolicyInstallScript':
            mgmt['install_script'] = {
                'enabled': _bool(child.get('enabled', 'False')),
                'command': child.get('command', ''),
                'arguments': child.get('arguments', ''),
            }
    return mgmt


def _address_type_attrs(addr, elem, known):
    """Parse type-specific address attributes into *addr*.

    Handles inet_addr_mask (IPv4/IPv6/Network), AddressRange
    start/end, and MultiAddressRunTime fields.  Adds consumed
    attribute names to *known*.
    """
    # address / netmask -> inet_addr_mask JSON
    address_str = elem.get('address')
    netmask_str = elem.get('netmask')
    if address_str is not None or netmask_str is not None:
        addr.inet_addr_mask = {}
        if address_str is not None:
            addr.inet_addr_mask['address'] = address_str
        if netmask_str is not None:
            addr.inet_addr_mask['netmask'] = netmask_str
        known |= {'address', 'netmask'}

    # AddressRange
    start = elem.get('start_address')
    end = elem.get('end_address')
    if start is not None:
        addr.start_address = {'address': start}
        known.add('start_address')
    if end is not None:
        addr.end_address = {'address': end}
        known.add('end_address')

    # MultiAddressRunTime
    if elem.get('subst_type_name') is not None:
        addr.subst_type_name = elem.get('subst_type_name')
        known.add('subst_type_name')
    if elem.get('source_name') is not None:
        addr.source_name = elem.get('source_name')
        known.add('source_name')
    if elem.get('run_time') is not None:
        addr.run_time = _bool(elem.get('run_time'))
        known.add('run_time')


def _service_type_attrs(svc, elem, known):
    """Parse type-specific service attributes into *svc*.

    Handles port ranges (TCP/UDP), TCP flags, IPService protocol_num,
    CustomService protocol/address_family, and UserService userid.
    Adds consumed attribute names to *known*.
    """
    # TCPUDPService port ranges
    if elem.get('src_range_start') is not None:
        svc.src_range_start = _int(elem.get('src_range_start'))
        svc.src_range_end = _int(elem.get('src_range_end'))
        svc.dst_range_start = _int(elem.get('dst_range_start'))
        svc.dst_range_end = _int(elem.get('dst_range_end'))
        known |= {'src_range_start', 'src_range_end',
                  'dst_range_start', 'dst_range_end'}

    # TCPService flags
    flag_names = ('urg', 'ack', 'psh', 'rst', 'syn', 'fin')
    if elem.get('ack_flag') is not None:
        svc.tcp_flags = {
            f: _bool(elem.get(f'{f}_flag', 'False'))
            for f in flag_names
        }
        svc.tcp_flags_masks = {
            f: _bool(elem.get(f'{f}_flag_mask', 'False'))
            for f in flag_names
        }
        known |= {f'{f}_flag' for f in flag_names}
        known |= {f'{f}_flag_mask' for f in flag_names}

    # IPService
    if elem.get('protocol_num') is not None:
        svc.named_protocols = {
            'protocol_num': elem.get('protocol_num'),
        }
        known.add('protocol_num')

    # CustomService
    if elem.get('protocol') is not None:
        svc.protocol = elem.get('protocol')
        known.add('protocol')
    if elem.get('address_family') is not None:
        known.add('address_family')

    # UserService
    if elem.get('userid') is not None:
        svc.userid = elem.get('userid')
        known.add('userid')


def _service_codes(elem):
    """Parse ``<CustomServiceCommand>`` children into a dict, or None."""
    codes = {}
    for child in elem:
        if _tag(child) == 'CustomServiceCommand':
            platform = child.get('platform', '')
            codes[platform] = child.text or ''
    return codes or None


def _parse_rule_children(rule, elem):
    """Parse slot containers and options from rule children.

    Returns ``(options, negations)`` where *options* is a dict of
    non-column attributes (merged with any ``*RuleOptions`` children)
    and *negations* maps slot names to their negation flag.
    """
    known = {'id', 'name', 'comment', 'position', 'action', 'direction'}
    options = {k: v for k, v in elem.attrib.items() if k not in known}
    negations = {}

    for child in elem:
        tag = _tag(child)
        if tag in _SLOT_NAMES:
            slot = _SLOT_NAMES[tag]
            negations[slot] = _bool(child.get('neg', 'False'))
            for ref_elem in child:
                if _tag(ref_elem) in _REF_TAGS:
                    ref_id = ref_elem.get('ref', '')
                    if ref_id:
                        yield rule.id, slot, ref_id
        elif tag in _OPTIONS_TAGS:
            options.update(_parse_options_children(child))

    rule.options = options
    rule.negations = negations


class XmlReader:
    def __init__(self):
        self._id_map = {}
        self._memberships = []
        self._rule_element_rows = []
        self._deferred_memberships = []
        self._deferred_rule_elements = []

    def _register(self, xml_id):
        """Map *xml_id* to a new UUID (or return an existing one)."""
        if xml_id in self._id_map:
            return self._id_map[xml_id]
        new_uuid = uuid.uuid4()
        self._id_map[xml_id] = new_uuid
        return new_uuid

    def _add_membership(self, group_id, member_id):
        """Record a group-membership association-table row."""
        self._memberships.append({
            'group_id': group_id,
            'member_id': member_id,
        })

    def parse(self, path):
        """Parse a ``.fwb`` file and return a :class:`ParseResult`."""
        self._id_map.clear()
        self._memberships.clear()
        self._rule_element_rows.clear()
        self._deferred_memberships.clear()
        self._deferred_rule_elements.clear()

        tree = xml.etree.ElementTree.parse(path)
        database = self._parse_database(tree.getroot())
        self._resolve_deferred()
        return ParseResult(
            database=database,
            memberships=self._memberships[:],
            rule_element_rows=self._rule_element_rows[:],
        )

    def _resolve_deferred(self):
        for group_id, ref_id in self._deferred_memberships:
            target_id = self._id_map.get(ref_id)
            if target_id is None:
                logger.warning('Unresolved group member reference: %s', ref_id)
                continue
            self._add_membership(group_id, target_id)
        for rule_id, slot, ref_id in self._deferred_rule_elements:
            target_id = self._id_map.get(ref_id)
            if target_id is None:
                logger.warning('Unresolved rule element reference: %s', ref_id)
                continue
            self._rule_element_rows.append({
                'rule_id': rule_id,
                'slot': slot,
                'target_id': target_id,
            })

    def _parse_database(self, elem):
        db = models.FWObjectDatabase()
        db.id = self._register(elem.get('id', 'root'))
        db.last_modified = float(elem.get('lastModified', '0'))
        db.data = _extra_attrs(elem, {'id', 'lastModified'})

        for child in elem:
            if _tag(child) == 'Library':
                self._parse_library(child, db)
        return db

    def _parse_library(self, elem, database):
        lib = models.Library()
        lib.id = self._register(elem.get('id', ''))
        lib.name = elem.get('name', '')
        lib.comment = elem.get('comment', '')
        lib.ro = _bool(elem.get('ro', 'False'))
        lib.data = _extra_attrs(elem, _COMMON_KNOWN)
        lib.database = database

        for child in elem:
            self._dispatch_child(child, lib, context_name=lib.name)
        return lib

    def _dispatch_child(self, elem, library, parent_group=None, context_name=''):
        """Dispatch a child element of a Library or Group."""
        tag = _tag(elem)

        if tag in _GROUP_TAGS:
            self._parse_group(elem, _GROUP_TAGS[tag], library, parent_group)
        elif tag in _ADDRESS_TAGS:
            self._parse_address(elem, library=library,
                                parent_group=parent_group)
        elif tag in _SERVICE_TAGS:
            self._parse_service(elem, library=library,
                                parent_group=parent_group)
        elif tag in ('Interval', 'AnyInterval'):
            self._parse_interval(elem, library=library,
                                 parent_group=parent_group)
        elif tag in _DEVICE_TAGS:
            self._parse_device(elem, _DEVICE_TAGS[tag], library,
                               parent_group=parent_group)
        elif tag in _REF_TAGS:
            if parent_group is not None:
                ref_id = elem.get('ref', '')
                if ref_id:
                    self._deferred_memberships.append(
                        (parent_group.id, ref_id))
            else:
                logger.debug('Skipping top-level %s in library %s', tag, context_name)
        elif tag in ('Interface', 'DummyInterface') and parent_group is None:
            # Orphaned interface (Deleted Objects) -- register IDs only
            xml_id = elem.get('id', '')
            if xml_id:
                self._register(xml_id)
            if tag == 'Interface':
                for child in elem:
                    if _tag(child) in _ADDRESS_TAGS:
                        child_id = child.get('id', '')
                        if child_id:
                            self._register(child_id)
            logger.debug('Skipping orphaned %s %s in library %s', tag, xml_id, context_name)
        else:
            logger.warning('Unhandled child: %s (in %s)', tag, context_name)

    def _parse_group(self, elem, cls, library, parent_group):
        group = cls()
        group.id = self._register(elem.get('id', ''))
        group.name = elem.get('name', '')
        group.comment = elem.get('comment', '')
        group.ro = _bool(elem.get('ro', 'False'))
        group.data = _extra_attrs(elem, _COMMON_KNOWN)
        group.library = library

        if parent_group is not None:
            group.parent_group = parent_group

        for child in elem:
            self._dispatch_child(child, library, parent_group=group, context_name=group.name)
        return group

    def _parse_device(self, elem, cls, library, parent_group=None):
        device = cls()
        device.id = self._register(elem.get('id', ''))
        device.name = elem.get('name', '')
        device.comment = elem.get('comment', '')
        device.ro = _bool(elem.get('ro', 'False'))
        device.data = _extra_attrs(elem, _COMMON_KNOWN)
        device.library = library

        if parent_group is not None:
            self._add_membership(parent_group.id, device.id)

        for child in elem:
            tag = _tag(child)
            if tag == 'Interface':
                self._parse_interface(child, device)
            elif tag in _RULESET_TAGS:
                self._parse_ruleset(child, _RULESET_TAGS[tag], device)
            elif tag == 'Management':
                device.management = _parse_management_elem(child)
            elif tag in _OPTIONS_TAGS:
                device.options = _parse_options_children(child)
            elif tag in _GROUP_TAGS:
                # ClusterGroup etc. inside a Cluster device
                self._parse_group(child, _GROUP_TAGS[tag], library, None)
            else:
                logger.warning('Unhandled device child: %s (in %s)', tag, device.name)
        return device

    def _parse_interface(self, elem, device):
        iface = models.Interface()
        iface.id = self._register(elem.get('id', ''))
        iface.name = elem.get('name', '')
        iface.comment = elem.get('comment', '')
        iface.data = _extra_attrs(elem, _COMMON_KNOWN)
        iface.device = device

        for child in elem:
            tag = _tag(child)
            if tag in _ADDRESS_TAGS:
                self._parse_address(child, interface=iface)
            elif tag in _OPTIONS_TAGS:
                iface.options = _parse_options_children(child)
            else:
                logger.warning('Unhandled interface child: %s (in %s)', tag, iface.name)
        return iface

    def _parse_address(self, elem, library=None, parent_group=None, interface=None):
        tag = _tag(elem)
        cls = _ADDRESS_TAGS.get(tag, models.Address)

        addr = cls()
        addr.id = self._register(elem.get('id', ''))
        addr.name = elem.get('name', '')
        addr.comment = elem.get('comment', '')

        known = set(_COMMON_KNOWN)
        _address_type_attrs(addr, elem, known)
        addr.data = _extra_attrs(elem, known)

        if interface is not None:
            addr.interface = interface
        elif library is not None:
            addr.library = library

        if parent_group is not None:
            self._add_membership(parent_group.id, addr.id)
        return addr

    def _parse_service(self, elem, library, parent_group=None):
        tag = _tag(elem)
        cls = _SERVICE_TAGS.get(tag, models.Service)

        svc = cls()
        svc.id = self._register(elem.get('id', ''))
        svc.name = elem.get('name', '')
        svc.comment = elem.get('comment', '')
        svc.library = library

        known = set(_COMMON_KNOWN)
        _service_type_attrs(svc, elem, known)
        svc.data = _extra_attrs(elem, known)

        codes = _service_codes(elem)
        if codes:
            svc.codes = codes

        if parent_group is not None:
            self._add_membership(parent_group.id, svc.id)
        return svc

    def _parse_interval(self, elem, library, parent_group=None):
        itv = models.Interval()
        itv.id = self._register(elem.get('id', ''))
        itv.name = elem.get('name', '')
        itv.comment = elem.get('comment', '')
        itv.data = _extra_attrs(elem, _COMMON_KNOWN)
        itv.library = library

        if parent_group is not None:
            self._add_membership(parent_group.id, itv.id)
        return itv

    def _parse_ruleset(self, elem, cls, device):
        rs = cls()
        rs.id = self._register(elem.get('id', ''))
        rs.name = elem.get('name', '')
        rs.comment = elem.get('comment', '')
        rs.ipv4 = _bool(elem.get('ipv4_rule_set', 'False'))
        rs.ipv6 = _bool(elem.get('ipv6_rule_set', 'False'))
        rs.top = _bool(elem.get('top_rule_set', 'False'))
        rs.device = device

        for child in elem:
            tag = _tag(child)
            if tag in _RULE_TAGS:
                self._parse_rule(child, _RULE_TAGS[tag], rs)
            elif tag in _OPTIONS_TAGS:
                rs.options = _parse_options_children(child)
            else:
                logger.warning('Unhandled ruleset child: %s (in %s)', tag, rs.name)
        return rs

    def _parse_rule(self, elem, cls, rule_set):
        rule = cls()
        rule.id = self._register(elem.get('id', ''))
        rule.name = elem.get('name', '')
        rule.comment = elem.get('comment', '')
        rule.position = _int(elem.get('position', '0'))
        rule.rule_set = rule_set

        # Type-specific columns
        if cls is models.PolicyRule:
            rule.policy_action = _POLICY_ACTIONS.get(
                elem.get('action', ''), 0)
            rule.policy_direction = _DIRECTIONS.get(
                elem.get('direction', ''), 0)
        elif cls is models.NATRule:
            rule.nat_action = _NAT_ACTIONS.get(
                elem.get('action', ''), 0)

        for rule_id, slot, ref_id in _parse_rule_children(rule, elem):
            self._deferred_rule_elements.append((rule_id, slot, ref_id))

        return rule
