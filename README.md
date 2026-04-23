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

### Installing a Release Candidate

To test a pre-release version, either allow pre-releases or pin a specific RC version:

```bash
uvx --from 'firewallfabrik[gui]' --prerelease allow fwf
uv tool install 'firewallfabrik[gui]' --prerelease allow
uv tool install 'firewallfabrik[gui]==<version>' --prerelease allow
```

For the full installation guide (pipx, pip, development setup, native themes, desktop integration), see the [User Guide: Installing FirewallFabrik](docs/user-guide/02%20-%20Installing%20FirewallFabrik.md).


## Documentation

Full documentation is available at [linuxfabrik.github.io/firewallfabrik](https://linuxfabrik.github.io/firewallfabrik/). It is automatically built and deployed on every push to `main`.


## Feedback from our Community

Some comments from the community about our successor to FirewallBuilder:

> First of all, we're so glad that there's finally a successor to Firewall Builder. Great porting job, guys! We've been using Firewall Builder on macOS to generate iptables firewalls for our various servers we're running out there. But with the ascent of nftables we began fearing that we might run into a problem in the future. Running FirewallFabrik under macOS works without a fuzz...

-- [Jürgen Nagel](https://github.com/juergennagel)


> ... Danke, das Du/Ihr FirewallFabrik ins Leben gerufen habt! Ich liebe FirewallBuilder und finde es wirklich ganz toll, ein Nachfolgeprodukt in FirewallFabrik gefunden zu haben. nftables-Unterstützung ist SUPER!

-- [Klaus Tachtler](https://github.com/tachtler)


> Thank you for this software, I loved FirewallBuilder, I imagine I'll love this one too.

-- [David Mercereau](https://github.com/kepon85)


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
