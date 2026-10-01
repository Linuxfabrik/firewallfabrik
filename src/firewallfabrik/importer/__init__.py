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

"""Import a running firewall's ruleset as a FirewallFabrik firewall.

Two inputs, one result: :func:`parse_iptables_save` reads iptables-save
and ip6tables-save, :func:`parse_nft_json` reads ``nft -j list ruleset``,
both into the same neutral model, :func:`parse_ip_route_json` reads the
routes of ``ip -j route``, and :func:`plan_import` and
:func:`apply_plan` turn that model into objects of the open data file.
"""

from firewallfabrik.importer._apply import apply_plan, plan_import
from firewallfabrik.importer._builder import ImportPlan, parse_ip_addr_json
from firewallfabrik.importer._iptables import parse_iptables_save
from firewallfabrik.importer._nftables import parse_nft_json
from firewallfabrik.importer._routes import parse_ip_route_json

__all__ = [
    'ImportPlan',
    'apply_plan',
    'parse_ip_addr_json',
    'parse_ip_route_json',
    'parse_iptables_save',
    'parse_nft_json',
    'plan_import',
]
