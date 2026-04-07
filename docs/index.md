# Linuxfabrik FirewallFabrik

Modern successor to Firewall Builder: Qt GUI for managing iptables/nftables policies. Centralized policy DB with reusable objects, scales to hundreds of firewalls, generates deployment-ready shell scripts.

Made by [Linuxfabrik](https://www.linuxfabrik.ch).


## Overview

FirewallFabrik is a modern successor to [Firewall Builder](https://github.com/fwbuilder/fwbuilder), preserving its core design philosophy while updating it for current firewall technologies. It is a Qt-based GUI that manages firewall policies for multiple platforms, including iptables and nftables, from a single unified interface. All objects, rules, and device definitions are stored in a centralized policy database, allowing consistent reuse of services, networks, and rule sets. This architecture scales cleanly from a handful of devices to hundreds of firewalls, all managed from one policy file and one UI, with platform-specific configuration generated automatically.


## Quick Start

1. Install: `uvx --from 'firewallfabrik[gui]' fwf`
2. Read the [User Guide](user-guide/01 - Introduction.md)
3. Migrating? See [Migrating from Firewall Builder](user-guide/17 - Migrating from Firewall Builder.md)


## Links

- [GitHub Repository](https://github.com/Linuxfabrik/firewallfabrik)
- [PyPI](https://pypi.org/project/firewallfabrik/)
- [Report an Issue](https://github.com/Linuxfabrik/firewallfabrik/issues/new/choose)
- [Linuxfabrik Website](https://www.linuxfabrik.ch)
