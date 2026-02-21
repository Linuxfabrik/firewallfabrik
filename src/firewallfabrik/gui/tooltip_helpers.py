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

"""Shared tooltip builders for ORM objects.

Mirrors fwbuilder's ``FWObjectPropertiesFactory::getObjectPropertiesDetailed()``.
Used by both the object tree and the policy/NAT/routing rule editor.
"""

from datetime import UTC, datetime

from firewallfabrik.gui.platform_settings import HOST_OS


def get_library_name(obj):
    """Return the name of the library containing *obj*, or empty string."""
    type_str = getattr(obj, 'type', type(obj).__name__)
    if type_str == 'Library':
        return obj.name
    try:
        lib = getattr(obj, 'library', None)
        if lib is not None:
            return lib.name
        # Address → interface → device → library
        iface = getattr(obj, 'interface', None)
        if iface is not None:
            lib = getattr(iface, 'library', None)
            if lib is not None:
                return lib.name
            device = getattr(iface, 'device', None)
            if device is not None:
                lib = getattr(device, 'library', None)
                if lib is not None:
                    return lib.name
        # RuleSet → device → library
        device = getattr(obj, 'device', None)
        if device is not None:
            lib = getattr(device, 'library', None)
            if lib is not None:
                return lib.name
    except Exception:
        pass
    return ''


def obj_tooltip(obj):
    """Return an HTML tooltip string for *obj*, matching fwbuilder's detailed format."""
    type_str = getattr(obj, 'type', type(obj).__name__)
    name = getattr(obj, 'name', '')
    lines = []

    # Library header (skip for Library objects themselves).
    if type_str != 'Library':
        lib_name = get_library_name(obj)
        if lib_name:
            lines.append(f'<b>Library:</b> {lib_name}')

    lines.append(f'<b>Object Type:</b> {type_str}')
    lines.append(f'<b>Object Name:</b> {name}')

    # -- Addresses --
    if type_str in ('IPv4', 'IPv6', 'Network', 'NetworkIPv6'):
        iam = getattr(obj, 'inet_addr_mask', None) or {}
        addr = iam.get('address', '')
        mask = iam.get('netmask', '')
        if addr:
            lines.append(f'{addr}/{mask}' if mask else addr)

    elif type_str == 'AddressRange':
        start = (getattr(obj, 'start_address', None) or {}).get('address', '')
        end = (getattr(obj, 'end_address', None) or {}).get('address', '')
        if start or end:
            lines.append(f'{start} - {end}')

    elif type_str == 'PhysAddress':
        iam = getattr(obj, 'inet_addr_mask', None) or {}
        mac = iam.get('address', '')
        if mac:
            lines.append(mac)

    elif type_str == 'DNSName':
        source = getattr(obj, 'source_name', None) or ''
        runtime = getattr(obj, 'run_time', None)
        if source:
            lines.append(f'<b>DNS record:</b> {source}')
        lines.append('Run-time' if runtime else 'Compile-time')

    elif type_str == 'AddressTable':
        source = getattr(obj, 'source_name', None) or ''
        runtime = getattr(obj, 'run_time', None)
        if source:
            lines.append(f'<b>Table file:</b> {source}')
        lines.append('Run-time' if runtime else 'Compile-time')

    # -- Devices --
    elif type_str in ('Cluster', 'Firewall'):
        data = getattr(obj, 'data', None) or {}
        platform = data.get('platform', '')
        version = data.get('version', '') or '- any -'
        host_os = data.get('host_OS', '')
        host_os = HOST_OS.get(host_os, host_os)
        ts_modified = int(data.get('lastModified', 0) or 0)
        ts_compiled = int(data.get('lastCompiled', 0) or 0)
        ts_installed = int(data.get('lastInstalled', 0) or 0)
        # Bold the most recent timestamp, show '-' for zero.
        ts_vals = {
            'Modified': ts_modified,
            'Compiled': ts_compiled,
            'Installed': ts_installed,
        }
        ts_max = max(ts_vals.values())
        ts_rows = ''
        for label, ts in ts_vals.items():
            if ts:
                text = datetime.fromtimestamp(ts, tz=UTC).strftime('%Y-%m-%d %H:%M:%S')
            else:
                text = '-'
            if ts and ts == ts_max:
                text = f'<b>{text}</b>'
            ts_rows += f'<tr><td>{label}:&nbsp;</td><td>{text}</td></tr>'
        lines.append(
            '<table cellspacing="0" cellpadding="0">'
            f'<tr><td>Platform:&nbsp;</td><td>{platform}</td></tr>'
            f'<tr><td>Version:&nbsp;</td><td>{version}</td></tr>'
            f'<tr><td>Host OS:&nbsp;</td><td>{host_os}</td></tr>'
            f'{ts_rows}'
            '</table>'
        )

    elif type_str == 'Host':
        # Show interfaces with their brief attributes.
        for iface in sorted(
            getattr(obj, 'interfaces', []), key=lambda o: o.name.lower()
        ):
            attrs = _iface_brief(iface)
            lines.append(f'{iface.name}: {attrs}')

    elif type_str == 'Interface':
        # Parent device.
        device = getattr(obj, 'device', None)
        if device is not None:
            lines.append(f'<b>Parent: </b>{device.name}')
        data = getattr(obj, 'data', None) or {}
        label = data.get('label', '')
        lines.append(f'<b>Label: </b>{label}')
        # IP addresses.
        for addr in getattr(obj, 'addresses', []):
            if getattr(addr, 'type', '') == 'PhysAddress':
                continue
            iam = getattr(addr, 'inet_addr_mask', None) or {}
            a = iam.get('address', '')
            if a:
                m = iam.get('netmask', '')
                lines.append(f'{a}/{m}' if m else a)
        # Interface type.
        options = getattr(obj, 'options', None) or {}
        intf_type = options.get('type', '')
        if intf_type:
            type_text = intf_type
            if intf_type == '8021q':
                vlan_id = options.get('vlan_id', '')
                if vlan_id:
                    type_text += f' VLAN ID={vlan_id}'
            lines.append(f'<b>Interface Type: </b>{type_text}')
        # MAC address.
        for addr in getattr(obj, 'addresses', []):
            if getattr(addr, 'type', '') == 'PhysAddress':
                iam = getattr(addr, 'inet_addr_mask', None) or {}
                mac = iam.get('address', '')
                if mac:
                    lines.append(f'MAC: {mac}')
        # Flags.
        flags = []
        if data.get('dyn'):
            flags.append('dyn')
        if data.get('unnum'):
            flags.append('unnum')
        if data.get('bridge_port'):
            flags.append('bridge port')
        if data.get('unprotected'):
            flags.append('unp')
        if flags:
            lines.append(f'({" ".join(flags)})')

    # -- Services --
    elif type_str in ('TCPService', 'UDPService'):
        ss = getattr(obj, 'src_range_start', None) or 0
        se = getattr(obj, 'src_range_end', None) or 0
        ds = getattr(obj, 'dst_range_start', None) or 0
        de = getattr(obj, 'dst_range_end', None) or 0
        lines.append(
            '<table cellspacing="0" cellpadding="0">'
            f'<tr><td>source port range&nbsp;</td><td>{ss}:{se}</td></tr>'
            f'<tr><td>destination port range&nbsp;</td><td>{ds}:{de}</td></tr>'
            '</table>'
        )

    elif type_str in ('ICMP6Service', 'ICMPService'):
        codes = getattr(obj, 'codes', None) or {}
        icmp_type = codes.get('type', -1)
        code = codes.get('code', -1)
        lines.append(f'type: {icmp_type}  code: {code}')

    elif type_str == 'IPService':
        named = getattr(obj, 'named_protocols', None) or {}
        protocol_num = named.get('protocol_num', '')
        if protocol_num:
            lines.append(f'protocol {protocol_num}')

    elif type_str == 'CustomService':
        codes = getattr(obj, 'codes', None) or {}
        if codes:
            rows = ''.join(
                f'<tr><td>{k}&nbsp;</td><td>{v}</td></tr>'
                for k, v in sorted(codes.items())
                if v
            )
            if rows:
                lines.append(f'<table cellspacing="0" cellpadding="0">{rows}</table>')

    elif type_str == 'TagService':
        data = getattr(obj, 'data', None) or {}
        tag_code = data.get('tagcode', '')
        if tag_code:
            lines.append(f'Pattern: "{tag_code}"')

    elif type_str == 'UserService':
        uid = getattr(obj, 'userid', None) or ''
        if uid:
            lines.append(f'User id: "{uid}"')

    # -- Groups --
    elif type_str in ('IntervalGroup', 'ObjectGroup', 'ServiceGroup'):
        members = []
        for attr in ('addresses', 'child_groups', 'devices', 'intervals', 'services'):
            val = getattr(obj, attr, None)
            if val:
                members.extend(val)
        count = len(members)
        lines.append(f'{count} objects')
        for m in sorted(members, key=lambda o: o.name.lower())[:20]:
            m_type = getattr(m, 'type', type(m).__name__)
            lines.append(f'{m_type}  <b>{m.name}</b>')
        if count > 20:
            lines.append('&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;.&nbsp;.&nbsp;.')

    # -- Library --
    elif type_str == 'Library':
        if getattr(obj, 'ro', False):
            lines.append('Read-only')

    # -- Comment --
    comment = getattr(obj, 'comment', None) or ''
    if comment:
        if len(comment) > 200:
            comment = comment[:200] + '\u2026'
        comment = (
            comment.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        )
        lines.append(f'<br><i>{comment}</i>')

    return '<br>'.join(lines)


def _iface_brief(iface):
    """Return a short attribute string for an interface (used in Host tooltip)."""
    data = getattr(iface, 'data', None) or {}
    parts = []
    for addr in getattr(iface, 'addresses', []):
        iam = getattr(addr, 'inet_addr_mask', None) or {}
        a = iam.get('address', '')
        if a:
            m = iam.get('netmask', '')
            parts.append(f'{a}/{m}' if m else a)
    flags = []
    if data.get('dyn'):
        flags.append('dyn')
    if data.get('unnum'):
        flags.append('unnum')
    if flags:
        parts.append(','.join(flags))
    return ' '.join(parts)
