<h1 align="center">
  <a href="https://linuxfabrik.ch" target="_blank">
    <picture>
      <img width="600" src="https://raw.githubusercontent.com/Linuxfabrik/firewallfabrik/refs/heads/main/src/firewallfabrik/resources/images/fwf.png">
    </picture>
  </a>
  <br />
  Linuxfabrik FirewallFabrik
</h1>
<p align="center">
  Modern fwbuilder successor: Qt GUI for managing iptables/nftables policies. Centralized policy DB with reusable objects, scales to hundreds of firewalls, generates deployment-ready shell scripts.
  <span>&#8226;</span>
  <b>made by <a href="https://linuxfabrik.ch/">Linuxfabrik</a></b>
</p>
<div align="center">

![GitHub Stars](https://img.shields.io/github/stars/linuxfabrik/firewallfabrik)
![License](https://img.shields.io/github/license/linuxfabrik/firewallfabrik)
![Version](https://img.shields.io/github/v/release/linuxfabrik/firewallfabrik?sort=semver)
[![PyPI](https://img.shields.io/pypi/v/firewallfabrik)](https://pypi.org/project/firewallfabrik/)
![Python](https://img.shields.io/badge/Python-3.14+-3776ab)
![GitHub Issues](https://img.shields.io/github/issues/linuxfabrik/firewallfabrik)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Linuxfabrik/firewallfabrik/badge)](https://scorecard.dev/viewer/?uri=github.com/Linuxfabrik/firewallfabrik)
[![GitHubSponsors](https://img.shields.io/github/sponsors/Linuxfabrik?label=GitHub%20Sponsors)](https://github.com/sponsors/Linuxfabrik)
[![PayPal](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=7AW3VVX62TR4A&source=url)

</div>

<br />

# FirewallFabrik

FirewallFabrik is a modern successor to [Firewall Builder](https://github.com/fwbuilder/fwbuilder) (fwbuilder), preserving its core design philosophy while updating it for current firewall technologies. It is a Qt-based GUI that manages firewall policies for multiple platforms, including iptables and nftables, from a single unified interface. All objects, rules, and device definitions are stored in a centralized policy database, allowing consistent reuse of services, networks, and rule sets. This architecture scales cleanly from a handful of devices to hundreds of firewalls, all managed from one policy file and one UI, with platform-specific configuration generated automatically.

This project was developed with the assistance of Claude Code by Anthropic.


## Installation

Make sure to include the `[gui]` extra to pull in PySide6 for the graphical interface.

### Using uv (recommended)

The recommended way to install FirewallFabrik. You can run it without a permanent install:

```bash
uvx --from 'firewallfabrik[gui]' fwf
```

Or install it as a tool:

```bash
uv tool install 'firewallfabrik[gui]'
```

For the full installation guide (pipx, pip, development setup, native themes, desktop integration), see the [User Guide: Installing FirewallFabrik](docs/user-guide/02%20-%20Installing%20FirewallFabrik.md).


## Documentation

* [User Guide](docs/user-guide/) -- installation, GUI overview, working with objects, firewall policies, cookbook, and more.
* [Migrating from Firewall Builder](docs/user-guide/17%20-%20Migrating%20from%20Firewall%20Builder.md) -- import .fwb files and differences.
* [Developer Guide](docs/developer-guide/) -- database manager, debugging, rule processors, testing, and design decisions.
* [Changelog](CHANGELOG.md) -- release history.
* [Contributing](CONTRIBUTING.md) -- how to contribute.
* [Issue Tracker](https://github.com/Linuxfabrik/firewallfabrik/issues) -- bug reports and feature requests.


### Source Code Documentation

To generate browsable API documentation for all Python modules:

```shell
pip install pdoc
pdoc --output-dir docs/source-code src/firewallfabrik
```

Open `docs/source-code/index.html` in a browser to view it.


## License

```python
# Copyright (C) 2026 Linuxfabrik <info@linuxfabrik.ch>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# On Debian systems, the complete text of the GNU General Public License
# version 2 can be found in /usr/share/common-licenses/GPL-2.

# SPDX-License-Identifier: GPL-2.0-or-later
```
