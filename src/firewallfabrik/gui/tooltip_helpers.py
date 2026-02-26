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
        addr = getattr(obj, 'inet_address', '') or ''
        mask = getattr(obj, 'inet_netmask', '') or ''
        if addr:
            lines.append(f'{addr}/{mask}' if mask else addr)

    elif type_str == 'AddressRange':
        start = getattr(obj, 'range_start', '') or ''
        end = getattr(obj, 'range_end', '') or ''
        if start or end:
            lines.append(f'{start} - {end}')

    elif type_str == 'PhysAddress':
        mac = getattr(obj, 'inet_address', '') or ''
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
            a = getattr(addr, 'inet_address', '') or ''
            if a:
                m = getattr(addr, 'inet_netmask', '') or ''
                lines.append(f'{a}/{m}' if m else a)
        # Interface type.
        intf_type = getattr(obj, 'opt_type', '') or ''
        if intf_type:
            type_text = intf_type
            if intf_type == '8021q':
                vlan_id = getattr(obj, 'opt_vlan_id', '') or ''
                if vlan_id:
                    type_text += f' VLAN ID={vlan_id}'
            lines.append(f'<b>Interface Type: </b>{type_text}')
        # MAC address.
        for addr in getattr(obj, 'addresses', []):
            if getattr(addr, 'type', '') == 'PhysAddress':
                mac = getattr(addr, 'inet_address', '') or ''
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
        icmp_type = getattr(obj, 'icmp_type', None)
        icmp_code = getattr(obj, 'icmp_code', None)
        t_str = icmp_type if icmp_type is not None else -1
        c_str = icmp_code if icmp_code is not None else -1
        lines.append(f'type: {t_str}  code: {c_str}')

    elif type_str == 'IPService':
        protocol_num = getattr(obj, 'protocol_num', None)
        if protocol_num is not None:
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
        tag_code = getattr(obj, 'tag_code', None) or ''
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
        a = getattr(addr, 'inet_address', '') or ''
        if a:
            m = getattr(addr, 'inet_netmask', '') or ''
            parts.append(f'{a}/{m}' if m else a)
    flags = []
    if data.get('dyn'):
        flags.append('dyn')
    if data.get('unnum'):
        flags.append('unnum')
    if flags:
        parts.append(','.join(flags))
    return ' '.join(parts)
