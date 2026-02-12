# FirewallFabrik

FirewallFabrik is a Qt-based GUI tool for managing firewall configurations across multiple platforms (iptables, nftables, etc.). Firewall configuration data is stored in a central file that can scale to hundreds of firewalls managed from a single UI.


## Installation

> **Note:** If you only want to run the CLI tools, use `firewallfabrik` instead of `firewallfabrik[gui]` in the following commands to avoid pulling in any GUI dependencies.

### From PyPI (Recommended)

FirewallFabrik releases are available from [PyPI](https://pypi.org/project/firewallfabrik/).

Using [uv](https://docs.astral.sh/uv/):

```shell
# Run FirewallFabrik without installing
uvx firewallfabrik[gui]

# Install FirewallFabrik
uv tool install firewallfabrik[gui]
```

Using [pipx](https://pipx.pypa.io):

```shell
pipx install firewallfabrik[gui]
```

Using standard pip (user install):

```shell
pip install --user firewallfabrik[gui]
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
pip install --editable .

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

* [Introduction](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/01%20-%20Introduction.rst)
* [Installing Firewall Builder](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/02%20-%20Installing%20Firewall%20Builder.rst)
* [Definitions and Terms](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/03%20-%20Definitions%20and%20Terms.rst)
* [Firewall Builder GUI](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/04%20-%20Firewall%20Builder%20GUI.rst)
* [Working with Objects](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/05%20-%20Working%20with%20Objects.rst)
* [Network Discovery](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/06%20-%20Network%20Discovery.rst)
* [Firewall Policies](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/07%20-%20Firewall%20Policies.rst)
* [Cluster Configuration](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/08%20-%20Cluster%20Configuration.rst)
* [Configuration of Interfaces](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/09%20-%20Configuration%20of%20Interfaces.rst)
* [Compiling and Installing a Policy](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/10%20-%20Compiling%20and%20Installing%20a%20Policy.rst)
* [Manage your Firewall Remotely](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/11%20-%20Manage%20your%20Firewall%20Remotely.rst)
* [Integration with OS Running on the Firewall Machine](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/12%20-%20Integration%20with%20OS%20Running%20on%20the%20Firewall%20Machine.rst)
* [Configlets](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/13%20-%20Configlets.rst)
* [Firewall Builder Cookbook](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/14%20-%20Firewall%20Builder%20Cookbook.rst)
* [Troubleshooting](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/15%20-%20Troubleshooting.rst)
* [Appendix](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/16%20-%20Appendix.rst)


## Design Decisions

PySide6 vs. PyQt6

* There is no strong technical reason to prefer PySide6 over PyQt6 for this project - both frameworks are perfectly suitable. We chose PySide6 primarily because FirewallFabrik is being ported from the original Firewall Builder C++/Qt codebase. PySide6's API closely mirrors C++ Qt, which makes the porting process more straightforward and keeps the Python code visually and structurally similar to the original implementation.
* Additionally, PySide6 is licensed under the LGPL, which is more permissive and leaves the door open for potential proprietary extensions in the future.

Removal of the "Deleted Objects" Feature from Firewall Builder

* In Firewall Builder, the "Deleted Objects" feature provides only very limited value. When an object is deleted, all references to it are immediately removed. As a result, restoring an object from "Deleted Objects" does not restore its original relationships, significantly reducing the usefulness of the feature.
* For this reason, we decided not to implement "Deleted Objects" in FirewallFabrik. Instead, we recommend using Git as a version control system. With the switch from an XML-based backend (Firewall Builder) to YAML (FirewallFabrik), Git makes it easy to restore deleted objects - including all their references - by reverting or inspecting previous revisions of the data files.


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
