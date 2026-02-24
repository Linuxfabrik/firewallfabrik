<h1 align="center">
  <a href="https://linuxfabrik.ch" target="_blank">
    <picture>
      <img width="600" src="https://raw.githubusercontent.com/Linuxfabrik/firewallfabrik/refs/heads/main/src/firewallfabrik/gui/ui/Icons/firewallfabrik.svg">
    </picture>
  </a>
  <br />
  Linuxfabrik's FirewallFabrik
</h1>
<p align="center">
  <em>FirewallFabrik</em>
  <span>&#8226;</span>
  <b>made by <a href="https://linuxfabrik.ch/">Linuxfabrik</a></b>
</p>
<div align="center">

![GitHub](https://img.shields.io/github/license/linuxfabrik/firewallfabrik)
![GitHub last commit](https://img.shields.io/github/last-commit/linuxfabrik/firewallfabrik)
![Version](https://img.shields.io/github/v/release/linuxfabrik/firewallfabrik?sort=semver)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Linuxfabrik/firewallfabrik/badge)](https://scorecard.dev/viewer/?uri=github.com/Linuxfabrik/firewallfabrik)
[![GitHubSponsors](https://img.shields.io/github/sponsors/Linuxfabrik?label=GitHub%20Sponsors)](https://github.com/sponsors/Linuxfabrik)
[![PayPal](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=7AW3VVX62TR4A&source=url)

</div>

<br />

# FirewallFabrik

FirewallFabrik is a modern successor to [Firewall Builder](https://github.com/fwbuilder/fwbuilder), preserving its core design philosophy while updating it for current firewall technologies. It is a Qt-based GUI that manages firewall policies for multiple platforms, including iptables and nftables, from a single unified interface. All objects, rules, and device definitions are stored in a centralized policy database, allowing consistent reuse of services, networks, and rule sets. This architecture scales cleanly from a handful of devices to hundreds of firewalls, all managed from one policy file and one UI, with platform-specific configuration generated automatically.


## Quick Start

```shell
# Run FirewallFabrik without installing (requires uv)
uvx --from 'firewallfabrik[gui]' fwf

# Or install it
uv tool install 'firewallfabrik[gui]'
```

For the full installation guide (pipx, pip, development setup, native themes, desktop integration), see the [User Guide: Installing FirewallFabrik](docs/user-guide/02%20-%20Installing%20FirewallFabrik.rst).


## Documentation

* [User Guide](docs/user-guide/) -- installation, GUI overview, working with objects, firewall policies, cookbook, and more.
* [Developer Guide](docs/developer-guide/) -- database manager, debugging, rule processors, testing, and design decisions.


### Building the Documentation

The documentation is built with [Sphinx](https://www.sphinx-doc.org/) using the Read the Docs theme. To build it locally:

```bash
pip install sphinx sphinx-rtd-theme myst-parser
cd docs
make html
```

The generated HTML will be in `docs/_build/html/`. Open `docs/_build/html/index.html` in a browser to view it.


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
