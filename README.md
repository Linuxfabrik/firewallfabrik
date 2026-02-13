<h1 align="center">
  <!--<a href="https://linuxfabrik.ch" target="_blank">
    <picture>
      <img width="600" src="https://download.linuxfabrik.ch/assets/linuxfabrik-fwf-teaser.png">
    </picture>
  </a>-->
  <br />
  Linuxfabrik FirewallFabrik
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

FirewallFabrik is a Qt-based GUI tool for managing firewall configurations across multiple platforms (iptables, nftables, etc.). Firewall configuration data is stored in a central file that can scale to hundreds of firewalls managed from a single UI.


## Installation

> **Note:** If you only want to run the CLI tools, use `firewallfabrik` instead of `firewallfabrik[gui]` in the following commands to avoid pulling in any GUI dependencies.

### From PyPI (Recommended)

FirewallFabrik releases are available from [PyPI](https://pypi.org/project/firewallfabrik/).

Using [uv](https://docs.astral.sh/uv/):

```shell
# Run FirewallFabrik without installing
uvx --from 'firewallfabrik[gui]' fwf

# Install FirewallFabrik
uv tool install 'firewallfabrik[gui]'
```

Using [pipx](https://pipx.pypa.io):

```shell
pipx install 'firewallfabrik[gui]'
```

Using standard pip (user install):

```shell
pip install --user 'firewallfabrik[gui]'
```

Please note that on certain Linux systems `--break-system-packages`
might need to be added when using the system's Python/Pip.


### From Git (For Development or Power Users)

* Clone this repository.
* To install FirewallFabrik, at the root of the repo, run `pip install .`
* For development use `--editable` to install FirewallFabrik in [Development/Editable Mode](https://setuptools.pypa.io/en/latest/userguide/development_mode.html).
* The usage of a virtual environment is *strongly recommended*.

For example:

```bash
python3.14 -m venv $HOME/venvs/firewallfabrik
source $HOME/venvs/firewallfabrik/bin/activate
pip install --upgrade pip
pip install --editable '.[gui]' # add `--group dev` for development dependencies

# run
fwf
```


### Desktop Entry (Linux)

To integrate FirewallFabrik with your desktop environment (application icon in dock, app switcher, etc.), install the `.desktop` file and icon:

```bash
cp assets/ch.linuxfabrik.firewallfabrik.desktop $HOME/.local/share/applications/
mkdir -p $HOME/.local/share/icons/hicolor/scalable/apps/
cp src/firewallfabrik/gui/ui/Icons/firewallfabrik.svg $HOME/.local/share/icons/hicolor/scalable/apps/
update-desktop-database $HOME/.local/share/applications/ 2>/dev/null
gtk-update-icon-cache $HOME/.local/share/icons/hicolor/ 2>/dev/null
```

> **Note:** The `.desktop` file uses `Exec=fwf`, which requires `fwf` to be on your system `PATH`. This works out of the box with `pipx install` or `pip install --user`. If you installed FirewallFabrik in a **virtual environment**, edit the installed `.desktop` file and replace `fwf` with the absolute path:
>
> ```bash
> sed -i "s|Exec=fwf|Exec=$VIRTUAL_ENV/bin/fwf|" $HOME/.local/share/applications/ch.linuxfabrik.firewallfabrik.desktop
> ```


### Linux Native Themes

Some Linux distros provide a native PySide6 package. This package can be used for a more modern and integrated theme.

To use the native PySide6, the respective package needs to be installed using the native package manager and firewallfabrik needs to be installed without the `gui` 'extra' (just `pip install firewallfabrik` instead of `pip install firewallfabrik[gui]`).

When using tools such as `pipx` and `uv tool` or a virtual environment they must be initialised using the `--system-site-packages` to inherit the native PySide6 package. A user installation with standard pip should pick up the system package automatically.

Native Packages:
- Fedora: `dnf install python3-pyside6`
- Other Distros: Check your distro's package manager for PySide6


## Documentation

Source Code Documentation:

```shell
pdoc --output-dir docs/source-code src/firewallfabrik
```

This generates browsable HTML documentation for all Python modules into `docs/source-code/`. Open `docs/source-code/index.html` in a browser to view it.

User Guide:

* See https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide


## Design Decisions

PySide6 vs. PyQt6

* There is no strong technical reason to prefer PySide6 over PyQt6 for this project - both frameworks are perfectly suitable. We chose PySide6 primarily because FirewallFabrik is being ported from the original Firewall Builder C++/Qt codebase. PySide6's API closely mirrors C++ Qt, which makes the porting process more straightforward and keeps the Python code visually and structurally similar to the original implementation.
* Additionally, PySide6 is licensed under the LGPL, which is more permissive and leaves the door open for potential proprietary extensions in the future.

Removal of the "Deleted Objects" Feature from Firewall Builder

* In Firewall Builder, the "Deleted Objects" feature provides only very limited value. When an object is deleted, all references to it are immediately removed. As a result, restoring an object from "Deleted Objects" does not restore its original relationships, significantly reducing the usefulness of the feature.
* For this reason, we decided not to implement "Deleted Objects" in FirewallFabrik. Instead, we recommend using Git as a version control system. With the switch from an XML-based backend (Firewall Builder) to YAML (FirewallFabrik), Git makes it easy to restore deleted objects - including all their references - by reverting or inspecting previous revisions of the data files.

Changed the host settings default for "IPv4 Packet forwarding" from "On" to "No change"

* This option is only needed for firewalls that actually forward traffic, so it shouldn't be set by default.

The names and identifiers "linux24", "Linux2.4/2.6", "Linux" all refer to the same host OS and do not correspond to a specific Linux version. These names are kept for backward compatibility.

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
